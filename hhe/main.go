package main

import (
	ckksfv "HHELand/rtf_integration"
	"HHELand/rtf_integration/ring"
	"HHELand/utils"
	"crypto/rand"
	"fmt"
	"github.com/tuneinsight/lattigo/v6/utils/sampling"
	"golang.org/x/crypto/sha3"
	"math"
	"os"
)

// findHeraModDown(4, 0, 2, false)
func findHeraModDown(numRound int, paramIndex int, radix int, fullCoeffs bool) {
	var err error

	var kgen ckksfv.KeyGenerator
	var fvEncoder ckksfv.MFVEncoder
	var sk *ckksfv.SecretKey
	var pk *ckksfv.PublicKey
	var fvEncryptor ckksfv.MFVEncryptor
	var fvDecryptor ckksfv.MFVDecryptor
	var fvEvaluator ckksfv.MFVEvaluator
	var fvNoiseEstimator ckksfv.MFVNoiseEstimator
	var hera ckksfv.MFVHera

	var nonces [][]byte
	var key []uint64
	var stCt []*ckksfv.Ciphertext
	var keystream [][]uint64

	var heraModDown []int
	var stcModDown []int

	// RtF parameters
	// Four sets of parameters (index 0 to 3) ensuring 128 bit of security
	// are available in github.com/smilecjf/lattigo/v2/ckks_fv/rtf_params
	// LogSlots is hardcoded in the parameters, but can be changed from 4 to 15.
	// When changing logSlots make sure that the number of levels allocated to CtS is
	// smaller or equal to logSlots.

	hbtpParams := ckksfv.RtFHeraParams[paramIndex]
	params, err := hbtpParams.Params()
	if err != nil {
		panic(err)
	}

	// fullCoeffs denotes whether full coefficients are used for data encoding
	if fullCoeffs {
		params.SetLogFVSlots(params.LogN())
	} else {
		params.SetLogFVSlots(params.LogSlots())
	}

	// Scheme context and keys
	kgen = ckksfv.NewKeyGenerator(params)

	sk, pk = kgen.GenKeyPairSparse(hbtpParams.H)

	fvEncoder = ckksfv.NewMFVEncoder(params)

	fvEncryptor = ckksfv.NewMFVEncryptorFromPk(params, pk)
	fvDecryptor = ckksfv.NewMFVDecryptor(params, sk)
	fvNoiseEstimator = ckksfv.NewMFVNoiseEstimator(params, sk)

	pDcds := fvEncoder.GenSlotToCoeffMatFV(radix)
	rotations := kgen.GenRotationIndexesForSlotsToCoeffsMat(pDcds)
	rotkeys := kgen.GenRotationKeysForRotations(rotations, true, sk)
	rlk := kgen.GenRelinearizationKey(sk)

	fvEvaluator = ckksfv.NewMFVEvaluator(params, ckksfv.EvaluationKey{Rlk: rlk, Rtks: rotkeys}, pDcds)

	// Generating data set
	key = make([]uint64, 16)
	for i := 0; i < 16; i++ {
		key[i] = uint64(i + 1) // Use (1, ..., 16) for testing
	}

	nonces = make([][]byte, params.FVSlots())
	for i := 0; i < params.FVSlots(); i++ {
		nonces[i] = make([]byte, 64)
		rand.Read(nonces[i])
	}

	keystream = make([][]uint64, params.FVSlots())
	for i := 0; i < params.FVSlots(); i++ {
		keystream[i] = plainHera(numRound, nonces[i], key, params.PlainModulus())
	}

	// Find proper nbInitModDown value for fvHera
	fmt.Println("=========== Start to find nbInitModDown ===========")
	hera = ckksfv.NewMFVHera(numRound, params, fvEncoder, fvEncryptor, fvEvaluator, 0)
	heKey := hera.EncKey(key)
	stCt = hera.CryptNoModSwitch(nonces, heKey)

	invBudgets := make([]int, 16)
	minInvBudget := int((^uint(0)) >> 1) // MaxInt
	for i := 0; i < 16; i++ {
		ksSlot := fvEvaluator.SlotsToCoeffsNoModSwitch(stCt[i])

		invBudgets[i] = fvNoiseEstimator.InvariantNoiseBudget(ksSlot)
		if invBudgets[i] < minInvBudget {
			minInvBudget = invBudgets[i]
		}
		fvEvaluator.ModSwitchMany(ksSlot, ksSlot, ksSlot.Level())

		ksCt := fvDecryptor.DecryptNew(ksSlot)
		ksCoef := ckksfv.NewPlaintextRingT(params)
		fvEncoder.DecodeRingT(ksCt, ksCoef)

		for j := 0; j < params.FVSlots(); j++ {
			br_j := utils.BitReverse64(uint64(j), uint64(params.LogN()))

			if ksCoef.Element.Value()[0].Coeffs[0][br_j] != keystream[j][i] {
				fmt.Printf("[-] Validity failed")
				os.Exit(0)
			}
		}
	}
	fmt.Printf("Budget info : min %d in %v\n", minInvBudget, invBudgets)

	qi := params.Qi()
	qiCount := params.QiCount()
	logQi := make([]int, qiCount)
	for i := 0; i < qiCount; i++ {
		logQi[i] = int(math.Round(math.Log2(float64(qi[i]))))
	}

	nbInitModDown := 0
	cutBits := logQi[qiCount-1]
	for cutBits+40 < minInvBudget { // if minInvBudget is too close to cutBits, decryption can be failed
		nbInitModDown++
		cutBits += logQi[qiCount-nbInitModDown-1]
	}
	fmt.Printf("Preferred nbInitModDown = %d\n\n", nbInitModDown)

	fmt.Println("=========== Start to find HeraModDown & StcModDown ===========")
	hera = ckksfv.NewMFVHera(numRound, params, fvEncoder, fvEncryptor, fvEvaluator, nbInitModDown)
	heKey = hera.EncKey(key)
	stCt, heraModDown = hera.CryptAutoModSwitch(nonces, heKey, fvNoiseEstimator)
	_, stcModDown = fvEvaluator.SlotsToCoeffsAutoModSwitch(stCt[0], fvNoiseEstimator)
	for i := 0; i < 16; i++ {
		ksSlot := fvEvaluator.SlotsToCoeffs(stCt[i], stcModDown)
		if ksSlot.Level() > 0 {
			fvEvaluator.ModSwitchMany(ksSlot, ksSlot, ksSlot.Level())
		}

		ksCt := fvDecryptor.DecryptNew(ksSlot)
		ksCoef := ckksfv.NewPlaintextRingT(params)
		fvEncoder.DecodeRingT(ksCt, ksCoef)

		for j := 0; j < params.FVSlots(); j++ {
			br_j := utils.BitReverse64(uint64(j), uint64(params.LogN()))

			if ksCoef.Element.Value()[0].Coeffs[0][br_j] != keystream[j][i] {
				fmt.Printf("[-] Validity failed")
				os.Exit(0)
			}
		}
	}

	fmt.Printf("Hera modDown : %v\n", heraModDown)
	fmt.Printf("SlotsToCoeffs modDown : %v\n", stcModDown)
}

func plainHera(roundNum int, nonce []byte, key []uint64, plainModulus uint64) (state []uint64) {
	nr := roundNum
	xof := sha3.NewShake256()
	xof.Write(nonce)
	state = make([]uint64, 16)

	rks := make([][]uint64, nr+1)

	for r := 0; r <= nr; r++ {
		rks[r] = make([]uint64, 16)
		for st := 0; st < 16; st++ {
			rks[r][st] = ckksfv.SampleZqx(xof, plainModulus) * key[st] % plainModulus
		}
	}

	for i := 0; i < 16; i++ {
		state[i] = uint64(i + 1)
	}

	// round0
	for st := 0; st < 16; st++ {
		state[st] = (state[st] + rks[0][st]) % plainModulus
	}

	for r := 1; r < roundNum; r++ {
		for col := 0; col < 4; col++ {
			y0 := 2*state[col] + 3*state[col+4] + 1*state[col+8] + 1*state[col+12]
			y1 := 2*state[col+4] + 3*state[col+8] + 1*state[col+12] + 1*state[col]
			y2 := 2*state[col+8] + 3*state[col+12] + 1*state[col] + 1*state[col+4]
			y3 := 2*state[col+12] + 3*state[col] + 1*state[col+4] + 1*state[col+8]

			state[col] = y0 % plainModulus
			state[col+4] = y1 % plainModulus
			state[col+8] = y2 % plainModulus
			state[col+12] = y3 % plainModulus
		}

		for row := 0; row < 4; row++ {
			y0 := 2*state[4*row] + 3*state[4*row+1] + 1*state[4*row+2] + 1*state[4*row+3]
			y1 := 2*state[4*row+1] + 3*state[4*row+2] + 1*state[4*row+3] + 1*state[4*row]
			y2 := 2*state[4*row+2] + 3*state[4*row+3] + 1*state[4*row] + 1*state[4*row+1]
			y3 := 2*state[4*row+3] + 3*state[4*row] + 1*state[4*row+1] + 1*state[4*row+2]

			state[4*row] = y0 % plainModulus
			state[4*row+1] = y1 % plainModulus
			state[4*row+2] = y2 % plainModulus
			state[4*row+3] = y3 % plainModulus
		}

		for st := 0; st < 16; st++ {
			state[st] = (state[st] * state[st] % plainModulus) * state[st] % plainModulus
		}

		for st := 0; st < 16; st++ {
			state[st] = (state[st] + rks[r][st]) % plainModulus
		}
	}
	for col := 0; col < 4; col++ {
		y0 := 2*state[col] + 3*state[col+4] + 1*state[col+8] + 1*state[col+12]
		y1 := 2*state[col+4] + 3*state[col+8] + 1*state[col+12] + 1*state[col]
		y2 := 2*state[col+8] + 3*state[col+12] + 1*state[col] + 1*state[col+4]
		y3 := 2*state[col+12] + 3*state[col] + 1*state[col+4] + 1*state[col+8]

		state[col] = y0 % plainModulus
		state[col+4] = y1 % plainModulus
		state[col+8] = y2 % plainModulus
		state[col+12] = y3 % plainModulus
	}

	for row := 0; row < 4; row++ {
		y0 := 2*state[4*row] + 3*state[4*row+1] + 1*state[4*row+2] + 1*state[4*row+3]
		y1 := 2*state[4*row+1] + 3*state[4*row+2] + 1*state[4*row+3] + 1*state[4*row]
		y2 := 2*state[4*row+2] + 3*state[4*row+3] + 1*state[4*row] + 1*state[4*row+1]
		y3 := 2*state[4*row+3] + 3*state[4*row] + 1*state[4*row+1] + 1*state[4*row+2]

		state[4*row] = y0 % plainModulus
		state[4*row+1] = y1 % plainModulus
		state[4*row+2] = y2 % plainModulus
		state[4*row+3] = y3 % plainModulus
	}

	for st := 0; st < 16; st++ {
		state[st] = (state[st] * state[st] % plainModulus) * state[st] % plainModulus
	}

	for col := 0; col < 4; col++ {
		y0 := 2*state[col] + 3*state[col+4] + 1*state[col+8] + 1*state[col+12]
		y1 := 2*state[col+4] + 3*state[col+8] + 1*state[col+12] + 1*state[col]
		y2 := 2*state[col+8] + 3*state[col+12] + 1*state[col] + 1*state[col+4]
		y3 := 2*state[col+12] + 3*state[col] + 1*state[col+4] + 1*state[col+8]

		state[col] = y0 % plainModulus
		state[col+4] = y1 % plainModulus
		state[col+8] = y2 % plainModulus
		state[col+12] = y3 % plainModulus
	}

	for row := 0; row < 4; row++ {
		y0 := 2*state[4*row] + 3*state[4*row+1] + 1*state[4*row+2] + 1*state[4*row+3]
		y1 := 2*state[4*row+1] + 3*state[4*row+2] + 1*state[4*row+3] + 1*state[4*row]
		y2 := 2*state[4*row+2] + 3*state[4*row+3] + 1*state[4*row] + 1*state[4*row+1]
		y3 := 2*state[4*row+3] + 3*state[4*row] + 1*state[4*row+1] + 1*state[4*row+2]

		state[4*row] = y0 % plainModulus
		state[4*row+1] = y1 % plainModulus
		state[4*row+2] = y2 % plainModulus
		state[4*row+3] = y3 % plainModulus
	}

	for st := 0; st < 16; st++ {
		state[st] = (state[st] + rks[roundNum][st]) % plainModulus
	}
	return
}

func plainRubato(blocksize int, numRound int, nonce []byte, counter []byte, key []uint64, plainModulus uint64, sigma float64) (state []uint64) {
	xof := sha3.NewShake256()
	xof.Write(nonce)
	xof.Write(counter)
	state = make([]uint64, blocksize)

	prng, err := sampling.NewPRNG()
	if err != nil {
		panic(err)
	}
	gaussianSampler := ring.NewGaussianSampler(prng)

	rks := make([][]uint64, numRound+1)

	for r := 0; r <= numRound; r++ {
		rks[r] = make([]uint64, blocksize)
		for i := 0; i < blocksize; i++ {
			rks[r][i] = ckksfv.SampleZqx(xof, plainModulus) * key[i] % plainModulus
		}
	}

	// init state with numbers between 1 and blockSize
	for i := 0; i < blocksize; i++ {
		state[i] = uint64(i + 1)
	}

	// Initial AddRoundKey
	for i := 0; i < blocksize; i++ {
		state[i] = (state[i] + rks[0][i]) % plainModulus
	}

	// Round Functions
	for r := 1; r < numRound; r++ {
		rubatoLinearLayer(state, plainModulus)
		rubatoFeistel(state, plainModulus)
		for i := 0; i < blocksize; i++ {
			state[i] = (state[i] + rks[r][i]) % plainModulus
		}
	}

	// Finalization
	rubatoLinearLayer(state, plainModulus)
	rubatoFeistel(state, plainModulus)
	rubatoLinearLayer(state, plainModulus)
	if sigma > 0 {
		rubatoAddGaussianNoise(state, plainModulus, gaussianSampler, sigma)
	}
	for i := 0; i < blocksize; i++ {
		state[i] = (state[i] + rks[numRound][i]) % plainModulus
	}
	state = state[0 : blocksize-4]

	return
}

func rubatoLinearLayer(state []uint64, plainModulus uint64) {
	blocksize := len(state)
	buf := make([]uint64, blocksize)

	if blocksize == 16 {
		// MixColumns
		for row := 0; row < 4; row++ {
			for col := 0; col < 4; col++ {
				buf[row*4+col] = 2 * state[row*4+col]
				buf[row*4+col] += 3 * state[((row+1)%4)*4+col]
				buf[row*4+col] += state[((row+2)%4)*4+col]
				buf[row*4+col] += state[((row+3)%4)*4+col]
				buf[row*4+col] %= plainModulus
			}
		}
		// MixRows
		for row := 0; row < 4; row++ {
			for col := 0; col < 4; col++ {
				state[row*4+col] = 2 * buf[row*4+col]
				state[row*4+col] += 3 * buf[row*4+(col+1)%4]
				state[row*4+col] += buf[row*4+(col+2)%4]
				state[row*4+col] += buf[row*4+(col+3)%4]
				state[row*4+col] %= plainModulus
			}
		}
	} else if blocksize == 36 {
		// MixColumns
		for row := 0; row < 6; row++ {
			for col := 0; col < 6; col++ {
				buf[row*6+col] = 4 * state[row*6+col]
				buf[row*6+col] += 2 * state[((row+1)%6)*6+col]
				buf[row*6+col] += 4 * state[((row+2)%6)*6+col]
				buf[row*6+col] += 3 * state[((row+3)%6)*6+col]
				buf[row*6+col] += state[((row+4)%6)*6+col]
				buf[row*6+col] += state[((row+5)%6)*6+col]
				buf[row*6+col] %= plainModulus
			}
		}
		// MixRows
		for row := 0; row < 6; row++ {
			for col := 0; col < 6; col++ {
				state[row*6+col] = 4 * buf[row*6+col]
				state[row*6+col] += 2 * buf[row*6+(col+1)%6]
				state[row*6+col] += 4 * buf[row*6+(col+2)%6]
				state[row*6+col] += 3 * buf[row*6+(col+3)%6]
				state[row*6+col] += buf[row*6+(col+4)%6]
				state[row*6+col] += buf[row*6+(col+5)%6]
				state[row*6+col] %= plainModulus
			}
		}
	} else if blocksize == 64 {
		// MixColumns
		for row := 0; row < 8; row++ {
			for col := 0; col < 8; col++ {
				buf[row*8+col] = 5 * state[row*8+col]
				buf[row*8+col] += 3 * state[((row+1)%8)*8+col]
				buf[row*8+col] += 4 * state[((row+2)%8)*8+col]
				buf[row*8+col] += 3 * state[((row+3)%8)*8+col]
				buf[row*8+col] += 6 * state[((row+4)%8)*8+col]
				buf[row*8+col] += 2 * state[((row+5)%8)*8+col]
				buf[row*8+col] += state[((row+6)%8)*8+col]
				buf[row*8+col] += state[((row+7)%8)*8+col]
				buf[row*8+col] %= plainModulus
			}
		}
		// MixRows
		for row := 0; row < 8; row++ {
			for col := 0; col < 8; col++ {
				state[row*8+col] = 5 * buf[row*8+col]
				state[row*8+col] += 3 * buf[row*8+(col+1)%8]
				state[row*8+col] += 4 * buf[row*8+(col+2)%8]
				state[row*8+col] += 3 * buf[row*8+(col+3)%8]
				state[row*8+col] += 6 * buf[row*8+(col+4)%8]
				state[row*8+col] += 2 * buf[row*8+(col+5)%8]
				state[row*8+col] += buf[row*8+(col+6)%8]
				state[row*8+col] += buf[row*8+(col+7)%8]
				state[row*8+col] %= plainModulus
			}
		}
	} else {
		panic("Invalid blocksize")
	}
}

func rubatoFeistel(state []uint64, plainModulus uint64) {
	blocksize := len(state)
	buf := make([]uint64, blocksize)

	for i := 0; i < blocksize; i++ {
		buf[i] = state[i]
	}

	for i := 1; i < blocksize; i++ {
		state[i] = (buf[i] + buf[i-1]*buf[i-1]) % plainModulus
	}
}

func rubatoAddGaussianNoise(state []uint64, plainModulus uint64, gaussianSampler *ring.GaussianSampler, sigma float64) {
	bound := int(6 * sigma)
	gaussianSampler.AGN(state, plainModulus, sigma, bound)
}

func testPlainRubato(rubatoParam int) {
	numRound := ckksfv.RubatoParams[rubatoParam].NumRound
	blocksize := ckksfv.RubatoParams[rubatoParam].Blocksize
	nonce := make([]byte, 8)
	counter := make([]byte, 8)
	key := make([]uint64, blocksize)
	t := ckksfv.RubatoParams[rubatoParam].PlainModulus
	sigma := ckksfv.RubatoParams[rubatoParam].Sigma

	// Generate secret key
	for i := 0; i < blocksize; i++ {
		key[i] = uint64(i+1) % t
	}

	// Generate nonce
	for i := 0; i < 8; i++ {
		nonce[i] = byte(0)
		counter[i] = byte(0)
	}

	state := plainRubato(blocksize, numRound, nonce, counter, key, t, sigma)
	fmt.Println(state)
}

func testFVRubato(rubatoParam int) {
	var kgen ckksfv.KeyGenerator
	var fvEncoder ckksfv.MFVEncoder
	var sk *ckksfv.SecretKey
	var pk *ckksfv.PublicKey
	var fvEncryptor ckksfv.MFVEncryptor
	var fvDecryptor ckksfv.MFVDecryptor
	var fvEvaluator ckksfv.MFVEvaluator
	var fvNoiseEstimator ckksfv.MFVNoiseEstimator
	var rubato ckksfv.MFVRubato

	var nonces [][]byte
	var key []uint64
	var keystream [][]uint64
	var keystreamCt []*ckksfv.Ciphertext

	blocksize := ckksfv.RubatoParams[rubatoParam].Blocksize
	numRound := ckksfv.RubatoParams[rubatoParam].NumRound
	plainModulus := ckksfv.RubatoParams[rubatoParam].PlainModulus
	sigma := ckksfv.RubatoParams[rubatoParam].Sigma

	hbtpParams := ckksfv.RtFRubatoParams[0]
	params, err := hbtpParams.Params()
	if err != nil {
		panic(err)
	}

	params.SetPlainModulus(plainModulus)
	params.SetLogFVSlots(params.LogN())

	// Scheme context and keys
	fmt.Println("Key generation...")
	kgen = ckksfv.NewKeyGenerator(params)

	sk, pk = kgen.GenKeyPairSparse(192)

	fvEncoder = ckksfv.NewMFVEncoder(params)
	fvEncryptor = ckksfv.NewMFVEncryptorFromPk(params, pk)
	fvDecryptor = ckksfv.NewMFVDecryptor(params, sk)
	fvNoiseEstimator = ckksfv.NewMFVNoiseEstimator(params, sk)

	rlk := kgen.GenRelinearizationKey(sk)
	fvEvaluator = ckksfv.NewMFVEvaluator(params, ckksfv.EvaluationKey{Rlk: rlk}, nil)

	// Generating data set
	key = make([]uint64, blocksize)
	for i := 0; i < blocksize; i++ {
		key[i] = uint64(i + 1)
	}

	nonces = make([][]byte, params.FVSlots())
	for i := 0; i < params.FVSlots(); i++ {
		nonces[i] = make([]byte, 8)
		// rand.Read(nonces[i])
		for j := 0; j < 8; j++ {
			nonces[i][j] = byte(0)
		}
	}
	counter := make([]byte, 8)

	// Compute plain Rubato keystream
	fmt.Println("Computing plain keystream...")
	keystream = make([][]uint64, params.FVSlots())
	for i := 0; i < params.FVSlots(); i++ {
		keystream[i] = plainRubato(blocksize, numRound, nonces[i], counter, key, plainModulus, sigma)
	}

	// Evaluate the Rubato keystream
	fmt.Println("Evaluating HE keystream...")
	rubato = ckksfv.NewMFVRubato(rubatoParam, params, fvEncoder, fvEncryptor, fvEvaluator, 0)
	hekey := rubato.EncKey(key)
	budget := fvNoiseEstimator.InvariantNoiseBudget(hekey[0])
	fmt.Printf("Initial noise budget: %d\n", budget)
	keystreamCt = rubato.CryptNoModSwitch(nonces, counter, hekey)
	budget = fvNoiseEstimator.InvariantNoiseBudget(keystreamCt[0])
	fmt.Printf("Output noise budget: %d\n", budget)

	// Decrypt and decode the Rubato keystream
	for i := 0; i < blocksize-4; i++ {
		val := fvEncoder.DecodeUintSmallNew(fvDecryptor.DecryptNew(keystreamCt[i]))
		resString := fmt.Sprintf("keystream[%d]: he(%d), plain(%d)", i, val[0], keystream[0][i])
		fmt.Println(resString)
	}
}

func testRtFRubatoModDown(rubatoParam int, paramIndex int, radix int, fullCoeffs bool) {
	var err error

	var hbtp *ckksfv.HalfBootstrapper
	var kgen ckksfv.KeyGenerator
	var fvEncoder ckksfv.MFVEncoder
	var ckksEncoder ckksfv.CKKSEncoder
	var ckksDecryptor ckksfv.CKKSDecryptor
	var sk *ckksfv.SecretKey
	var pk *ckksfv.PublicKey
	var fvEncryptor ckksfv.MFVEncryptor
	var fvEvaluator ckksfv.MFVEvaluator
	var plainCKKSRingTs []*ckksfv.PlaintextRingT
	var plaintexts []*ckksfv.Plaintext
	var rubato ckksfv.MFVRubato

	var data [][]float64
	var nonces [][]byte
	var counter []byte
	var key []uint64
	var keystream [][]uint64
	var fvKeystreams []*ckksfv.Ciphertext

	var rubatoModDown []int
	var stcModDown []int

	// Rubato parameter
	blocksize := ckksfv.RubatoParams[rubatoParam].Blocksize
	numRound := ckksfv.RubatoParams[rubatoParam].NumRound
	plainModulus := ckksfv.RubatoParams[rubatoParam].PlainModulus
	sigma := ckksfv.RubatoParams[rubatoParam].Sigma

	// RtF parameters
	// Four sets of parameters (index 0 to 3) ensuring 128 bit of security
	// are available in github.com/smilecjf/lattigo/v2/ckks_fv/rtf_params
	// LogSlots is hardcoded in the parameters, but can be changed from 4 to 15.
	// When changing logSlots make sure that the number of levels allocated to CtS is
	// smaller or equal to logSlots.

	hbtpParams := ckksfv.RtFRubatoParams[paramIndex]
	params, err := hbtpParams.Params()
	if err != nil {
		panic(err)
	}
	params.SetPlainModulus(plainModulus)
	messageScaling := float64(params.PlainModulus()) / (2 * hbtpParams.MessageRatio)

	// Rubato parameters in RtF
	rubatoModDown = make([]int, numRound)
	stcModDown = make([]int, 30)

	// fullCoeffs denotes whether full coefficients are used for data encoding
	if fullCoeffs {
		params.SetLogFVSlots(params.LogN())
	} else {
		params.SetLogFVSlots(params.LogSlots())
	}

	// Scheme context and keys
	kgen = ckksfv.NewKeyGenerator(params)

	sk, pk = kgen.GenKeyPairSparse(hbtpParams.H)

	fvEncoder = ckksfv.NewMFVEncoder(params)
	ckksEncoder = ckksfv.NewCKKSEncoder(params)
	fvEncryptor = ckksfv.NewMFVEncryptorFromPk(params, pk)
	ckksDecryptor = ckksfv.NewCKKSDecryptor(params, sk)

	// Generating half-bootstrapping keys
	rotationsHalfBoot := kgen.GenRotationIndexesForHalfBoot(params.LogSlots(), hbtpParams)
	pDcds := fvEncoder.GenSlotToCoeffMatFV(radix)
	rotationsStC := kgen.GenRotationIndexesForSlotsToCoeffsMat(pDcds)
	rotations := append(rotationsHalfBoot, rotationsStC...)
	if !fullCoeffs {
		rotations = append(rotations, params.Slots()/2)
	}
	rotkeys := kgen.GenRotationKeysForRotations(rotations, true, sk)
	rlk := kgen.GenRelinearizationKey(sk)
	hbtpKey := ckksfv.BootstrappingKey{Rlk: rlk, Rtks: rotkeys}

	if hbtp, err = ckksfv.NewHalfBootstrapper(params, hbtpParams, hbtpKey); err != nil {
		panic(err)
	}

	// Encode float data added by keystream to plaintext coefficients
	fvEvaluator = ckksfv.NewMFVEvaluator(params, ckksfv.EvaluationKey{Rlk: rlk, Rtks: rotkeys}, pDcds)
	outputsize := blocksize - 4
	coeffs := make([][]float64, outputsize)
	for s := 0; s < outputsize; s++ {
		coeffs[s] = make([]float64, params.N())
	}

	key = make([]uint64, blocksize)
	for i := 0; i < blocksize; i++ {
		key[i] = uint64(i + 1)
	}

	if fullCoeffs {
		data = make([][]float64, outputsize)
		for s := 0; s < outputsize; s++ {
			data[s] = make([]float64, params.N())
			for i := 0; i < params.N(); i++ {
				data[s][i] = utils.RandFloat64(-1, 1)
			}
		}

		nonces = make([][]byte, params.N())
		for i := 0; i < params.N(); i++ {
			nonces[i] = make([]byte, 64)
			rand.Read(nonces[i])
		}
		counter = make([]byte, 64)
		rand.Read(counter)

		keystream = make([][]uint64, params.N())
		for i := 0; i < params.N(); i++ {
			keystream[i] = plainRubato(blocksize, numRound, nonces[i], counter, key, params.PlainModulus(), sigma)
		}

		for s := 0; s < outputsize; s++ {
			for i := 0; i < params.N()/2; i++ {
				j := utils.BitReverse64(uint64(i), uint64(params.LogN()-1))
				coeffs[s][j] = data[s][i]
				coeffs[s][j+uint64(params.N()/2)] = data[s][i+params.N()/2]
			}
		}

		plainCKKSRingTs = make([]*ckksfv.PlaintextRingT, outputsize)
		for s := 0; s < outputsize; s++ {
			plainCKKSRingTs[s] = ckksEncoder.EncodeCoeffsRingTNew(coeffs[s], messageScaling)
			poly := plainCKKSRingTs[s].Value()[0]
			for i := 0; i < params.N(); i++ {
				j := utils.BitReverse64(uint64(i), uint64(params.LogN()))
				poly.Coeffs[0][j] = (poly.Coeffs[0][j] + keystream[i][s]) % params.PlainModulus()
			}
		}
	} else {
		data = make([][]float64, outputsize)
		for s := 0; s < outputsize; s++ {
			data[s] = make([]float64, params.Slots())
			for i := 0; i < params.Slots(); i++ {
				data[s][i] = utils.RandFloat64(-1, 1)
			}
		}

		nonces = make([][]byte, params.Slots())
		for i := 0; i < params.Slots(); i++ {
			nonces[i] = make([]byte, 64)
			rand.Read(nonces[i])
		}
		counter = make([]byte, 64)
		rand.Read(counter)

		keystream = make([][]uint64, params.Slots())
		for i := 0; i < params.Slots(); i++ {
			keystream[i] = plainRubato(blocksize, numRound, nonces[i], counter, key, params.PlainModulus(), sigma)
		}

		for s := 0; s < outputsize; s++ {
			for i := 0; i < params.Slots()/2; i++ {
				j := utils.BitReverse64(uint64(i), uint64(params.LogN()-1))
				coeffs[s][j] = data[s][i]
				coeffs[s][j+uint64(params.N()/2)] = data[s][i+params.Slots()/2]
			}
		}

		plainCKKSRingTs = make([]*ckksfv.PlaintextRingT, outputsize)
		for s := 0; s < outputsize; s++ {
			plainCKKSRingTs[s] = ckksEncoder.EncodeCoeffsRingTNew(coeffs[s], messageScaling)
			poly := plainCKKSRingTs[s].Value()[0]
			for i := 0; i < params.Slots(); i++ {
				j := utils.BitReverse64(uint64(i), uint64(params.LogN()))
				poly.Coeffs[0][j] = (poly.Coeffs[0][j] + keystream[i][s]) % params.PlainModulus()
			}
		}
	}

	plaintexts = make([]*ckksfv.Plaintext, outputsize)

	for s := 0; s < outputsize; s++ {
		plaintexts[s] = ckksfv.NewPlaintextFVLvl(params, 0)
		fvEncoder.FVScaleUp(plainCKKSRingTs[s], plaintexts[s])
	}

	rubato = ckksfv.NewMFVRubato(rubatoParam, params, fvEncoder, fvEncryptor, fvEvaluator, rubatoModDown[0])
	kCt := rubato.EncKey(key)

	// FV Keystream
	fvKeystreams = rubato.CryptNoModSwitch(nonces, counter, kCt)
	for i := 0; i < outputsize; i++ {
		fvKeystreams[i] = fvEvaluator.SlotsToCoeffs(fvKeystreams[i], stcModDown)
		fvEvaluator.ModSwitchMany(fvKeystreams[i], fvKeystreams[i], fvKeystreams[i].Level())
	}

	var ctBoot *ckksfv.Ciphertext
	for s := 0; s < outputsize; s++ {
		// Encrypt and mod switch to the lowest level
		ciphertext := ckksfv.NewCiphertextFVLvl(params, 1, 0)
		ciphertext.Value()[0] = plaintexts[s].Value()[0].CopyNew()
		fvEvaluator.Sub(ciphertext, fvKeystreams[s], ciphertext)
		fvEvaluator.TransformToNTT(ciphertext, ciphertext)
		ciphertext.SetScale(float64(params.Qi()[0]) / float64(params.PlainModulus()) * messageScaling)

		// Half-Bootstrap the ciphertext (homomorphic evaluation of ModRaise -> SubSum -> CtS -> EvalMod)
		// It takes a ciphertext at level 0 (if not at level 0, then it will reduce it to level 0)
		// and returns a ciphertext at level MaxLevel - k, where k is the depth of the bootstrapping circuit.
		// Difference from the bootstrapping is that the last StC is missing.
		// CAUTION: the scale of the ciphertext MUST be equal (or very close) to params.Scale
		// To equalize the scale, the function evaluator.SetScale(ciphertext, parameters.Scale) can be used at the expense of one level.
		if fullCoeffs {
			ctBoot, _ = hbtp.HalfBoot(ciphertext, false)
		} else {
			ctBoot, _ = hbtp.HalfBoot(ciphertext, true)
		}

		valuesWant := make([]complex128, params.Slots())
		for i := 0; i < params.Slots(); i++ {
			valuesWant[i] = complex(data[s][i], 0)
		}

		printString := fmt.Sprintf("Precision of HalfBoot(ciphertext[%d])", s)
		fmt.Println(printString)
		printDebug(params, ctBoot, valuesWant, ckksDecryptor, ckksEncoder)
	}
}

func printDebug(params *ckksfv.Parameters, ciphertext *ckksfv.Ciphertext, valuesWant []complex128, decryptor ckksfv.CKKSDecryptor, encoder ckksfv.CKKSEncoder) {

	valuesTest := encoder.DecodeComplex(decryptor.DecryptNew(ciphertext), params.LogSlots())
	logSlots := params.LogSlots()
	sigma := params.Sigma()

	fmt.Printf("Level: %d (logQ = %d)\n", ciphertext.Level(), params.LogQLvl(ciphertext.Level()))
	fmt.Printf("Scale: 2^%f\n", math.Log2(ciphertext.Scale()))
	fmt.Printf("ValuesTest: %6.10f %6.10f %6.10f %6.10f...\n", valuesTest[0], valuesTest[1], valuesTest[2], valuesTest[3])
	fmt.Printf("ValuesWant: %6.10f %6.10f %6.10f %6.10f...\n", valuesWant[0], valuesWant[1], valuesWant[2], valuesWant[3])

	precStats := ckksfv.GetPrecisionStats(params, encoder, nil, valuesWant, valuesTest, logSlots, sigma)

	fmt.Println(precStats.String())
}

func findRubatoModDown(rubatoParam int, radix int) {
	var err error

	var kgen ckksfv.KeyGenerator
	var fvEncoder ckksfv.MFVEncoder
	var sk *ckksfv.SecretKey
	var pk *ckksfv.PublicKey
	var fvEncryptor ckksfv.MFVEncryptor
	var fvDecryptor ckksfv.MFVDecryptor
	var fvEvaluator ckksfv.MFVEvaluator
	var fvNoiseEstimator ckksfv.MFVNoiseEstimator
	var rubato ckksfv.MFVRubato

	var nonces [][]byte
	var key []uint64
	var stCt []*ckksfv.Ciphertext
	var keystream [][]uint64

	var rubatoModDown []int
	var stcModDown []int

	// Rubato parameter
	blocksize := ckksfv.RubatoParams[rubatoParam].Blocksize
	numRound := ckksfv.RubatoParams[rubatoParam].NumRound
	plainModulus := ckksfv.RubatoParams[rubatoParam].PlainModulus

	// RtF Rubato parameters
	// Four sets of parameters (index 0 to 1) ensuring 128 bit of security
	// are available in github.com/smilecjf/lattigo/v2/ckks_fv/rtf_params
	// LogSlots is hardcoded in the parameters, but can be changed from 4 to 15.
	// When changing logSlots make sure that the number of levels allocated to CtS is
	// smaller or equal to logSlots.

	hbtpParams := ckksfv.RtFRubatoParams[0]
	params, err := hbtpParams.Params()
	if err != nil {
		panic(err)
	}
	params.SetPlainModulus(plainModulus)
	params.SetLogFVSlots(params.LogN())

	// Scheme context and keys
	kgen = ckksfv.NewKeyGenerator(params)
	sk, pk = kgen.GenKeyPairSparse(hbtpParams.H)

	fvEncoder = ckksfv.NewMFVEncoder(params)

	fvEncryptor = ckksfv.NewMFVEncryptorFromPk(params, pk)
	fvDecryptor = ckksfv.NewMFVDecryptor(params, sk)
	fvNoiseEstimator = ckksfv.NewMFVNoiseEstimator(params, sk)

	pDcds := fvEncoder.GenSlotToCoeffMatFV(radix)
	rotations := kgen.GenRotationIndexesForSlotsToCoeffsMat(pDcds)
	rotkeys := kgen.GenRotationKeysForRotations(rotations, true, sk)
	rlk := kgen.GenRelinearizationKey(sk)

	fvEvaluator = ckksfv.NewMFVEvaluator(params, ckksfv.EvaluationKey{Rlk: rlk, Rtks: rotkeys}, pDcds)

	// Generating data set
	key = make([]uint64, blocksize)
	for i := 0; i < blocksize; i++ {
		key[i] = uint64(i + 1) // Use (1, ..., 16) for testing
	}

	nonces = make([][]byte, params.FVSlots())
	for i := 0; i < params.FVSlots(); i++ {
		nonces[i] = make([]byte, 64)
		rand.Read(nonces[i])
	}
	counter := make([]byte, 64)
	rand.Read(counter)

	keystream = make([][]uint64, params.FVSlots())
	for i := 0; i < params.FVSlots(); i++ {
		keystream[i] = plainRubato(blocksize, numRound, nonces[i], counter, key, params.PlainModulus(), -1)
	}
	outputsize := blocksize - 4

	// Find proper nbInitModDown value for fvHera
	fmt.Println("=========== Start to find nbInitModDown ===========")
	rubato = ckksfv.NewMFVRubato(rubatoParam, params, fvEncoder, fvEncryptor, fvEvaluator, 0)
	heKey := rubato.EncKey(key)
	stCt = rubato.CryptNoModSwitch(nonces, counter, heKey)

	invBudgets := make([]int, outputsize)
	minInvBudget := int((^uint(0)) >> 1) // MaxInt
	for i := 0; i < outputsize; i++ {
		ksSlot := fvEvaluator.SlotsToCoeffsNoModSwitch(stCt[i])

		invBudgets[i] = fvNoiseEstimator.InvariantNoiseBudget(ksSlot)
		if invBudgets[i] < minInvBudget {
			minInvBudget = invBudgets[i]
		}
		fvEvaluator.ModSwitchMany(ksSlot, ksSlot, ksSlot.Level())

		ksCt := fvDecryptor.DecryptNew(ksSlot)
		ksCoef := ckksfv.NewPlaintextRingT(params)
		fvEncoder.DecodeRingT(ksCt, ksCoef)

		for j := 0; j < params.FVSlots(); j++ {
			br_j := utils.BitReverse64(uint64(j), uint64(params.LogN()))

			if ksCoef.Element.Value()[0].Coeffs[0][br_j] != keystream[j][i] {
				fmt.Printf("[-] Validity failed")
				os.Exit(0)
			}
		}
	}
	fmt.Printf("Budget info : min %d in %v\n", minInvBudget, invBudgets)

	qi := params.Qi()
	qiCount := params.QiCount()
	logQi := make([]int, qiCount)
	for i := 0; i < qiCount; i++ {
		logQi[i] = int(math.Round(math.Log2(float64(qi[i]))))
	}

	nbInitModDown := 0
	cutBits := logQi[qiCount-1]
	for cutBits+40 < minInvBudget { // if minInvBudget is too close to cutBits, decryption can be failed
		nbInitModDown++
		cutBits += logQi[qiCount-nbInitModDown-1]
	}
	fmt.Printf("Preferred nbInitModDown = %d\n\n", nbInitModDown)

	fmt.Println("=========== Start to find RubatoModDown & StcModDown ===========")
	rubato = ckksfv.NewMFVRubato(rubatoParam, params, fvEncoder, fvEncryptor, fvEvaluator, nbInitModDown)
	heKey = rubato.EncKey(key)
	stCt, rubatoModDown = rubato.CryptAutoModSwitch(nonces, counter, heKey, fvNoiseEstimator)
	_, stcModDown = fvEvaluator.SlotsToCoeffsAutoModSwitch(stCt[0], fvNoiseEstimator)
	for i := 0; i < outputsize; i++ {
		ksSlot := fvEvaluator.SlotsToCoeffs(stCt[i], stcModDown)
		if ksSlot.Level() > 0 {
			fvEvaluator.ModSwitchMany(ksSlot, ksSlot, ksSlot.Level())
		}

		ksCt := fvDecryptor.DecryptNew(ksSlot)
		ksCoef := ckksfv.NewPlaintextRingT(params)
		fvEncoder.DecodeRingT(ksCt, ksCoef)

		for j := 0; j < params.FVSlots(); j++ {
			br_j := utils.BitReverse64(uint64(j), uint64(params.LogN()))

			if ksCoef.Element.Value()[0].Coeffs[0][br_j] != keystream[j][i] {
				fmt.Printf("[-] Validity failed")
				os.Exit(0)
			}
		}
	}

	fmt.Printf("Rubato modDown : %v\n", rubatoModDown)
	fmt.Printf("SlotsToCoeffs modDown : %v\n", stcModDown)
}

func main() {
	findHeraModDown(4, 0, 2, false)
	// testPlainRubato(ckks_fv.RUBATO80L)
	// testFVRubato(ckks_fv.RUBATO80L)
	// findRubatoModDown(ckks_fv.RUBATO80S, 2)
}
