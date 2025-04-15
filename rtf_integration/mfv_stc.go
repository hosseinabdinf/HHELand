// Package rubato
// This file meant to be for slot to coefficient matrix generation, the original one does not support
// the serialization, therefore, one cannot generate and store the matrices for the server side
// todo: I (Hossein) will fix these later, after crypto deadline
package RtF

import (
	"HHELand/utils"

	"github.com/tuneinsight/lattigo/v6/ring"
	"github.com/tuneinsight/lattigo/v6/utils/structs"
)

//// PtDiagMatrixT is a struct storing a plaintext-diagonalized matrix
//// ready to be evaluated on a ciphertext using evaluator.MultiplyByDiagMatrice.
//type PtDiagMatrixT struct {
//	LogFVSlots int                   // Log of the number of slots of the plaintext
//	N1         int                   // N1 is the number of inner loops of the baby-step giant-step algo used in the evaluation
//	Vec        map[int][2]*ring.Poly // Vec is the matrix, in diagonal form, where each entry of vec is an indexed non zero diagonal
//	naive      bool
//}

type PolyMap structs.Map[int, [2]*ring.Poly]

// PlaintextDiagMatrixT is a struct storing a plaintext-diagonalized matrix,
// ready to be evaluated on a ciphertext using evaluator.MultiplyByDiagMatrice.
type PlaintextDiagMatrixT struct {
	LogFVSlots int
	N1         int
	Vec        PolyMap
	naive      bool
}

// GenSTCMatrix generates slot to coefficients matrix
func (encoder *mfvEncoder) GenSTCMatrix(radix int) (pDcds [][]*PlaintextDiagMatrixT) {
	params := encoder.params
	//modCount := len(params.qi)
	modCount := params.QiCount()
	pDcds = make([][]*PlaintextDiagMatrixT, modCount)

	var genDcdFunc func(logSlots int, plainModulus uint64) (plainVector []map[int][]uint64)
	switch radix {
	case 0:
		genDcdFunc = GenDecodingMatsInOne
	case 2:
		genDcdFunc = GenDecodingMatsRad2
	default:
		genDcdFunc = GenDecodingMats
	}
	for level := 0; level < modCount; level++ {
		pVecDcd := genDcdFunc(params.logFVSlots, params.plainModulus)
		pDcds[level] = make([]*PlaintextDiagMatrixT, len(pVecDcd))

		for i := 0; i < len(pDcds[level]); i++ {
			pDcds[level][i] = encoder.EncodeStCDiagMatrixT(level, pVecDcd[i], 16.0, params.logFVSlots)
		}
	}
	return
}

// EncodeStCDiagMatrixT encodes a diagonalized plaintext matrix into PtDiagMatrixT struct.
// It can then be evaluated on a ciphertext using evaluator.MultiplyByDiagMatrice.
// maxN1N2Ratio is the maximum ratio between the inner and outer loop of the baby-step giant-step algorithm
// used in evaluator.MultiplyByDiagMatrice. The Optimal maxN1N2Ratio value is between 4 and 16 depending on
// the sparsity of the matrix.
func (encoder *mfvEncoder) EncodeStCDiagMatrixT(level int, diagMatrix map[int][]uint64, maxN1N2Ratio float64, logFVSlots int) (matrix *PlaintextDiagMatrixT) {
	matrix = new(PlaintextDiagMatrixT)
	matrix.LogFVSlots = logFVSlots
	fvSlots := 1 << logFVSlots

	if len(diagMatrix) > 2 {
		// N1*N2 = N
		N1 := findbestbabygiantstepsplit(diagMatrix, fvSlots, maxN1N2Ratio)
		matrix.N1 = N1

		index, _ := bsgsIndex(diagMatrix, fvSlots, N1)

		matrix.Vec = make(PolyMap)

		for j := range index {
			for _, i := range index[j] {
				// manages inputs that have rotation between 0 and slots-1 or between -slots/2 and slots/2-1
				v := diagMatrix[N1*j+i]
				if len(v) == 0 {
					v = diagMatrix[(N1*j+i)-fvSlots]
				}

				//matrix.Vec[N1*j+i] = encoder.encodeStCDiagonalT(level, logFVSlots, rotateSmallT(v, -N1*j))
			}
		}
	} else {
		matrix.Vec = make(PolyMap)

		for i := range diagMatrix {
			idx := i
			if idx < 0 {
				idx += fvSlots
			}
			//matrix.Vec[idx] = encoder.encodeStCDiagonalT(level, logFVSlots, diagMatrix[i])
		}

		matrix.naive = true
	}

	return
}

func (encoder *mfvEncoder) encodeStCDiagonalT(level, logFVSlots int, m []uint64) [2]*ring.Poly {
	ringQ := encoder.ringQs[level]
	ringP := encoder.ringP
	ringT := encoder.ringT
	ringTSmall := encoder.ringTSmall
	tmp := encoder.tmpPolySmall

	// EncodeUintRingT
	for i := 0; i < len(m); i++ {
		tmp.Coeffs[0][encoder.indexMatrixSmall[i]] = m[i]
	}
	ringTSmall.InvNTT(tmp, tmp)

	mT := ringT.NewPoly()
	gap := 1 << (encoder.params.logN - logFVSlots)
	for i := 0; i < (1 << logFVSlots); i++ {
		mT.Coeffs[0][i*gap] = tmp.Coeffs[0][i]
	}

	// RingTToMulRingQ
	mQ := ringQ.NewPoly()
	for i := 0; i < len(ringQ.Modulus); i++ {
		copy(mQ.Coeffs[i], mT.Coeffs[0])
	}
	ringQ.NTTLazy(mQ, mQ)
	ringQ.MForm(mQ, mQ)

	// RingTToMulRingP
	mP := ringP.NewPoly()
	for i := 0; i < len(encoder.ringP.Modulus); i++ {
		copy(mP.Coeffs[i], mT.Coeffs[0])
	}
	ringP.NTTLazy(mP, mP)
	ringP.MForm(mP, mP)

	//return [2]*ring.Poly{mQ, mP}
	return [2]*ring.Poly{}
}

// GenDecodingMats generates decoding matrix that is factorized into sparse block diagonal matrices with radix 1
func GenDecodingMats(logSlots int, plainModulus uint64) (plainVector []map[int][]uint64) {
	roots := ComputePrimitiveRoots(1<<(logSlots+1), plainModulus)
	diabMats := GenDiagDecMatrix(logSlots, roots)
	depth := len(diabMats) - 1

	plainVector = make([]map[int][]uint64, depth)
	for i := 0; i < depth-2; i++ {
		plainVector[i] = diabMats[i]
	}
	plainVector[depth-2] = MulDiagMat(diabMats[depth-1], diabMats[depth-2], plainModulus)
	plainVector[depth-1] = MulDiagMat(diabMats[depth], diabMats[depth-2], plainModulus)
	return
}

// GenDecodingMatsRad2 generates decoding matrix that is factorized into sparse block diagonal matrices with radix 2
func GenDecodingMatsRad2(logSlots int, plainModulus uint64) (plainVector []map[int][]uint64) {
	roots := ComputePrimitiveRoots(1<<(logSlots+1), plainModulus)
	diabMats := GenDiagDecMatrix(logSlots, roots)
	depth := len(diabMats) - 1

	plainVector = make([]map[int][]uint64, (depth+1)/2+1)
	if depth%2 == 0 {
		for i := 0; i < depth-2; i += 2 {
			plainVector[i/2] = MulDiagMat(diabMats[i+1], diabMats[i], plainModulus)
		}
	} else {
		plainVector[0] = diabMats[0]
		for i := 1; i < depth-2; i += 2 {
			plainVector[(i+1)/2] = MulDiagMat(diabMats[i+1], diabMats[i], plainModulus)
		}
	}
	plainVector[(depth-1)/2] = MulDiagMat(diabMats[depth-1], diabMats[depth-2], plainModulus)
	plainVector[(depth+1)/2] = MulDiagMat(diabMats[depth], diabMats[depth-2], plainModulus)
	return
}

// GenDecodingMatsInOne generates decoding matrix which is not factorized
func GenDecodingMatsInOne(logSlots int, plainModulus uint64) (plainVector []map[int][]uint64) {
	if logSlots != 4 {
		panic("cannot GenDecodingMatsInOne: logSlots should be 4")
	}
	roots := ComputePrimitiveRoots(1<<(logSlots+1), plainModulus)
	diabMats := GenDiagDecMatrix(logSlots, roots)

	plainVector = make([]map[int][]uint64, 2)
	tmp := diabMats[0]
	tmp = MulDiagMat(diabMats[1], tmp, plainModulus)
	plainVector[0] = MulDiagMat(diabMats[2], tmp, plainModulus)
	plainVector[1] = MulDiagMat(diabMats[3], tmp, plainModulus)
	return
}

// MulDiagMat multiplies two diagonal block matrices (A and B) in diagonal form and modulo a plaintext modulus
func MulDiagMat(A map[int][]uint64, B map[int][]uint64, plainModulus uint64) (res map[int][]uint64) {
	res = make(map[int][]uint64)

	for rotA := range A {
		for rotB := range B {
			N := len(A[rotA])
			if res[(rotA+rotB)%(N/2)] == nil {
				res[(rotA+rotB)%(N/2)] = make([]uint64, N)
			}

			for i := 0; i < N/2; i++ {
				res[(rotA+rotB)%(N/2)][i] += A[rotA][i] * B[rotB][(rotA+i)%(N/2)]
				res[(rotA+rotB)%(N/2)][i] %= plainModulus

			}

			for i := N / 2; i < N; i++ {
				res[(rotA+rotB)%(N/2)][i] += A[rotA][i] * B[rotB][N/2+(rotA+i)%(N/2)]
				res[(rotA+rotB)%(N/2)][i] %= plainModulus
			}
		}
	}
	return
}

// GenDiagDecMatrix generates a factorized decomposition of a diagonal decoding matrix using powers of 5 and a given root table.
func GenDiagDecMatrix(logN int, roots []uint64) (res []map[int][]uint64) {
	N := 1 << logN
	M := 2 * N
	pow5 := make([]int, M)
	res = make([]map[int][]uint64, logN)

	for i, exp5 := 0, 1; i < N; i, exp5 = i+1, exp5*5%M {
		pow5[i] = exp5
	}
	res[0] = make(map[int][]uint64)
	res[0][0] = make([]uint64, N)
	res[0][1] = make([]uint64, N)
	res[0][2] = make([]uint64, N)
	res[0][3] = make([]uint64, N)
	res[0][N/2-1] = make([]uint64, N)
	res[0][N/2-2] = make([]uint64, N)
	res[0][N/2-3] = make([]uint64, N)
	for i := 0; i < N; i += 4 {
		res[0][0][i] = 1
		res[0][0][i+1] = roots[2*N/4]
		res[0][0][i+2] = roots[7*N/4]
		res[0][0][i+3] = roots[1*N/4]

		res[0][1][i] = roots[2*N/4]
		res[0][1][i+1] = roots[5*N/4]
		res[0][1][i+2] = roots[5*N/4]

		res[0][2][i] = roots[1*N/4]
		res[0][2][i+1] = roots[7*N/4]

		res[0][3][i] = roots[3*N/4]

		res[0][N/2-1][i+1] = 1
		res[0][N/2-1][i+2] = roots[6*N/4]
		res[0][N/2-1][i+3] = roots[3*N/4]

		res[0][N/2-2][i+2] = 1
		res[0][N/2-2][i+3] = roots[6*N/4]

		res[0][N/2-3][i+3] = 1
	}

	for ind := 1; ind < logN-2; ind++ {
		s := 1 << ind // size of each diabMat
		gap := N / s / 4

		res[ind] = make(map[int][]uint64)
		for _, rot := range []int{0, s, 2 * s, N/2 - s, N/2 - 2*s} {
			if res[ind][rot] == nil {
				res[ind][rot] = make([]uint64, N)
			}
		}

		for i := 0; i < N; i += 4 * s {
			/*
				[I 0 W0 0 ]
				[I 0 W1 0 ]
				[0 I 0 W0-]
				[0 I 0 W1-]
			*/
			for j := 0; j < s; j++ {
				res[ind][2*s][i+j] = roots[pow5[j]*gap%M]     // W0
				res[ind][s][i+s+j] = roots[pow5[s+j]*gap%M]   // W1
				res[ind][s][i+2*s+j] = roots[M-pow5[j]*gap%M] // W0-
				res[ind][0][i+j] = 1
				res[ind][0][i+3*s+j] = roots[M-pow5[s+j]*gap%M] // W1-
				res[ind][N/2-s][i+s+j] = 1
				res[ind][N/2-s][i+2*s+j] = 1
				res[ind][N/2-2*s][i+3*s+j] = 1
			}
		}
	}

	s := N / 4

	res[logN-2] = make(map[int][]uint64)
	res[logN-2][0] = make([]uint64, N)
	res[logN-2][s] = make([]uint64, N)

	res[logN-1] = make(map[int][]uint64)
	res[logN-1][0] = make([]uint64, N)
	res[logN-1][s] = make([]uint64, N)

	for i := 0; i < s; i++ {
		res[logN-2][0][i] = 1
		res[logN-2][0][i+3*s] = roots[M-pow5[s+i]%M]
		res[logN-2][s][i+s] = 1
		res[logN-2][s][i+2*s] = roots[M-pow5[i]%M]

		res[logN-1][0][i] = roots[pow5[i]%M]
		res[logN-1][0][i+3*s] = 1
		res[logN-1][s][i+s] = roots[pow5[s+i]%M]
		res[logN-1][s][i+2*s] = 1
	}
	return
}

// ComputePrimitiveRoots compute M-th root of unity
func ComputePrimitiveRoots(M int, plainModulus uint64) (roots []uint64) {
	g, _, err := ring.PrimitiveRoot(plainModulus, nil)
	utils.HandleError(err)
	e := uint64((int(plainModulus) - 1) / M)
	w := ring.ModExp(g, e, plainModulus)

	roots = make([]uint64, M)
	roots[0] = 1
	for i := 1; i < M; i++ {
		roots[i] = (roots[i-1] * w) % plainModulus
	}
	return
}
