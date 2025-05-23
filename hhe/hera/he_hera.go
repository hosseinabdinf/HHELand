package hera

import (
	"HHELand/rtf_integration"
	"HHELand/sym/hera"
	"HHELand/utils"
	"crypto/rand"
	"math"
)

type HEHera struct {
	logger           utils.Logger
	paramIndex       int
	fullCoefficients bool
	params           *RtF.Parameters
	symParams        hera.Parameter
	hbtp             *RtF.HalfBootstrapper
	hbtpParams       *RtF.HalfBootParameters
	keyGenerator     RtF.KeyGenerator
	fvEncoder        RtF.MFVEncoder
	ckksEncoder      RtF.CKKSEncoder
	ckksDecryptor    RtF.CKKSDecryptor
	sk               *RtF.SecretKey
	pk               *RtF.PublicKey
	fvEncryptor      RtF.MFVEncryptor
	fvEvaluator      RtF.MFVEvaluator
	plainCKKSRingTs  []*RtF.PlaintextRingT
	plaintexts       []*RtF.Plaintext

	fvHera         RtF.MFVHera
	messageScaling float64
	heraModDown    []int
	stcModDown     []int
	pDcds          [][]*RtF.PtDiagMatrixT
	rotkeys        *RtF.RotationKeySet
	rlk            *RtF.RelinearizationKey
	hbtpKey        RtF.BootstrappingKey

	N            int
	outSize      int
	coefficients [][]float64
	symKeyCt     []*RtF.Ciphertext
	ciphertext   *RtF.Ciphertext
}

func NewHEHera() *HEHera {
	hera := &HEHera{
		logger:           utils.NewLogger(utils.DEBUG),
		paramIndex:       0,
		fullCoefficients: true,
		params:           nil,
		symParams:        hera.Parameter{},
		hbtp:             nil,
		hbtpParams:       nil,
		keyGenerator:     nil,
		fvEncoder:        nil,
		ckksEncoder:      nil,
		ckksDecryptor:    nil,
		sk:               nil,
		pk:               nil,
		fvEncryptor:      nil,
		fvEvaluator:      nil,
		plainCKKSRingTs:  nil,
		plaintexts:       nil,
		fvHera:           nil,
		messageScaling:   0,
		heraModDown:      nil,
		stcModDown:       nil,
		pDcds:            nil,
		rotkeys:          nil,
		rlk:              nil,
		hbtpKey:          RtF.BootstrappingKey{},
		N:                0,
		outSize:          0,
		coefficients:     nil,
		symKeyCt:         nil,
		ciphertext:       nil,
	}
	return hera
}

func (hH *HEHera) InitParams(paramIndex int, symParams hera.Parameter) {
	var err error
	hH.paramIndex = paramIndex
	hH.symParams = symParams
	hH.outSize = symParams.BlockSize
	hH.hbtpParams = RtF.RtFHeraParams[paramIndex] // set to 2, using Hera 128af
	hH.params, err = hH.hbtpParams.Params()
	if err != nil {
		panic(err)
	}
	//hH.N = int(math.Ceil(float64(plainSize / hH.outSize)))
	hH.N = hH.params.N()
	hH.params.SetPlainModulus(symParams.GetModulus())
	hH.params.SetLogFVSlots(hH.params.LogN())
	hH.messageScaling = float64(hH.params.PlainModulus()) / hH.hbtpParams.MessageRatio
	if symParams.Rounds == 4 {
		hH.heraModDown = RtF.HeraModDownParams80[paramIndex].CipherModDown
		hH.stcModDown = RtF.HeraModDownParams80[paramIndex].StCModDown
	} else {
		hH.heraModDown = RtF.HeraModDownParams128[paramIndex].CipherModDown
		hH.stcModDown = RtF.HeraModDownParams128[paramIndex].StCModDown
	}
	// full Coefficients denotes whether full coefficients are used for data encoding
	switch paramIndex {
	case hera.HR128S, hera.HR128AS:
		hH.fullCoefficients = false
	case hera.HR128F, hera.HR128AF:
		hH.fullCoefficients = true
	}
	if hH.fullCoefficients {
		hH.params.SetLogFVSlots(hH.params.LogN())
	} else {
		hH.params.SetLogFVSlots(hH.params.LogSlots())
	}
}

func (hH *HEHera) HEKeyGen() {
	hH.keyGenerator = RtF.NewKeyGenerator(hH.params)
	hH.sk, hH.pk = hH.keyGenerator.GenKeyPairSparse(hH.hbtpParams.H)

	hH.fvEncoder = RtF.NewMFVEncoder(hH.params)
	hH.ckksEncoder = RtF.NewCKKSEncoder(hH.params)
	hH.fvEncryptor = RtF.NewMFVEncryptorFromPk(hH.params, hH.pk)
	hH.ckksDecryptor = RtF.NewCKKSDecryptor(hH.params, hH.sk)
}

func (hH *HEHera) HalfBootKeyGen(radix int) {
	// Generating half-bootstrapping keys
	rotationsHalfBoot := hH.keyGenerator.GenRotationIndexesForHalfBoot(hH.params.LogSlots(), hH.hbtpParams)
	hH.pDcds = hH.fvEncoder.GenSlotToCoeffMatFV(radix)
	rotationsStC := hH.keyGenerator.GenRotationIndexesForSlotsToCoeffsMat(hH.pDcds)
	rotations := append(rotationsHalfBoot, rotationsStC...)
	if !hH.fullCoefficients {
		rotations = append(rotations, hH.params.Slots()/2)
	}
	hH.rotkeys = hH.keyGenerator.GenRotationKeysForRotations(rotations, true, hH.sk)
	hH.rlk = hH.keyGenerator.GenRelinearizationKey(hH.sk)
	hH.hbtpKey = RtF.BootstrappingKey{Rlk: hH.rlk, Rtks: hH.rotkeys}
}

func (hH *HEHera) InitHalfBootstrapper() {
	var err error
	if hH.hbtp, err = RtF.NewHalfBootstrapper(hH.params, hH.hbtpParams, hH.hbtpKey); err != nil {
		panic(err)
	}
}

func (hH *HEHera) InitEvaluator() {
	hH.fvEvaluator = RtF.NewMFVEvaluator(hH.params, RtF.EvaluationKey{Rlk: hH.rlk, Rtks: hH.rotkeys}, hH.pDcds)
}

func (hH *HEHera) InitCoefficients() {
	hH.coefficients = make([][]float64, hH.outSize)
	for s := 0; s < hH.outSize; s++ {
		hH.coefficients[s] = make([]float64, hH.params.N())
	}
}

func (hH *HEHera) RandomDataGen(cols int) (data [][]float64) {
	data = make([][]float64, hH.outSize)
	for i := 0; i < hH.outSize; i++ {
		data[i] = make([]float64, cols)
		for j := 0; j < cols; j++ {
			data[i][j] = utils.RandFloat64(-1, 1)
		}
	}
	return
}

func (hH *HEHera) NonceGen(size int) (nonces [][]byte) {
	nonces = make([][]byte, size)
	for i := 0; i < size; i++ {
		nonces[i] = make([]byte, 64)
		rand.Read(nonces[i])
	}
	return
}

func (hH *HEHera) DataToCoefficients(data [][]float64, size int) {
	for s := 0; s < hH.outSize; s++ {
		for i := 0; i < size/2; i++ {
			j := utils.BitReverse64(uint64(i), uint64(hH.params.LogN()-1))
			hH.coefficients[s][j] = data[s][i]
			hH.coefficients[s][j+uint64(size/2)] = data[s][i+size/2]
		}
	}
}

func (hH *HEHera) EncodeEncrypt(keystream [][]uint64, size int) {
	hH.plainCKKSRingTs = make([]*RtF.PlaintextRingT, hH.outSize)
	for s := 0; s < hH.outSize; s++ {
		hH.plainCKKSRingTs[s] = hH.ckksEncoder.EncodeCoeffsRingTNew(hH.coefficients[s], hH.messageScaling)
		poly := hH.plainCKKSRingTs[s].Value()[0]
		for i := 0; i < size; i++ {
			j := utils.BitReverse64(uint64(i), uint64(hH.params.LogN()))
			poly.Coeffs[0][j] = (poly.Coeffs[0][j] + keystream[i][s]) % hH.params.PlainModulus()
		}
	}
}

func (hH *HEHera) ScaleUp() {
	hH.plaintexts = make([]*RtF.Plaintext, hH.outSize)
	for s := 0; s < hH.outSize; s++ {
		hH.plaintexts[s] = RtF.NewPlaintextFVLvl(hH.params, 0)
		hH.fvEncoder.FVScaleUp(hH.plainCKKSRingTs[s], hH.plaintexts[s])
	}
}

func (hH *HEHera) InitFvHera() RtF.MFVHera {
	hH.fvHera = RtF.NewMFVHera(hH.symParams.Rounds, hH.params, hH.fvEncoder, hH.fvEncryptor,
		hH.fvEvaluator, hH.heraModDown[0])
	return hH.fvHera
}

func (hH *HEHera) EncryptSymKey(key []uint64) {
	hH.symKeyCt = hH.fvHera.EncKey(key)
	hH.logger.PrintMessages(">> Symmetric Key Length: ", len(hH.symKeyCt))
}

func (hH *HEHera) GetFvKeyStreams(nonces [][]byte) []*RtF.Ciphertext {
	fvKeyStreams := hH.fvHera.Crypt(nonces, hH.symKeyCt, hH.heraModDown)
	for i := 0; i < hH.outSize; i++ {
		hH.logger.PrintMessages(">> index: ", i)
		fvKeyStreams[i] = hH.fvEvaluator.SlotsToCoeffs(fvKeyStreams[i], hH.stcModDown)
		hH.fvEvaluator.ModSwitchMany(fvKeyStreams[i], fvKeyStreams[i], fvKeyStreams[i].Level())
	}
	return fvKeyStreams
}

func (hH *HEHera) ScaleCiphertext(fvKeyStreams []*RtF.Ciphertext) {
	// Encrypt and mod switch to the lowest leve
	hH.ciphertext = RtF.NewCiphertextFVLvl(hH.params, 1, 0)
	hH.ciphertext.Value()[0] = hH.plaintexts[0].Value()[0].CopyNew()
	hH.fvEvaluator.Sub(hH.ciphertext, fvKeyStreams[0], hH.ciphertext)
	hH.fvEvaluator.TransformToNTT(hH.ciphertext, hH.ciphertext)
	hH.ciphertext.SetScale(
		math.Exp2(
			math.Round(
				math.Log2(
					float64(hH.params.Qi()[0]) /
						float64(hH.params.PlainModulus()) *
						hH.messageScaling,
				),
			),
		),
	)
}

func (hH *HEHera) HalfBoot() *RtF.Ciphertext {
	var ctBoot *RtF.Ciphertext
	if hH.fullCoefficients {
		ctBoot, _ = hH.hbtp.HalfBoot(hH.ciphertext, false)
	} else {
		ctBoot, _ = hH.hbtp.HalfBoot(hH.ciphertext, true)
	}
	return ctBoot
}
