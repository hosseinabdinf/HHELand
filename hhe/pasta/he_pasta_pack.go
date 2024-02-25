package pasta

import (
	"HHESoK"
	"HHESoK/rtf_ckks_integration/utils"
	"HHESoK/sym/pasta"
	"fmt"
	"github.com/tuneinsight/lattigo/v5/core/rlwe"
	"github.com/tuneinsight/lattigo/v5/schemes/bfv"
)

type HEPastaPack struct {
	logger  HHESoK.Logger
	fvPasta MFVPastaPack

	params    Parameter
	symParams pasta.Parameter
	bfvParams bfv.Parameters
	encoder   *bfv.Encoder
	evaluator *bfv.Evaluator
	encryptor *rlwe.Encryptor
	decryptor *rlwe.Decryptor

	keyGenerator *rlwe.KeyGenerator
	sk           *rlwe.SecretKey
	pk           *rlwe.PublicKey
	rlk          *rlwe.RelinearizationKey
	glk          []*rlwe.GaloisKey
	evk          *rlwe.MemEvaluationKeySet

	symKeyCt *rlwe.Ciphertext

	N       int
	outSize int
}

func NewHEPastaPack() *HEPastaPack {
	hePasta := &HEPastaPack{
		logger:       HHESoK.NewLogger(HHESoK.DEBUG),
		params:       Parameter{},
		symParams:    pasta.Parameter{},
		fvPasta:      nil,
		bfvParams:    bfv.Parameters{},
		encoder:      nil,
		evaluator:    nil,
		encryptor:    nil,
		decryptor:    nil,
		keyGenerator: nil,
		sk:           nil,
		pk:           nil,
		glk:          nil,
		rlk:          nil,
		evk:          nil,
		symKeyCt:     nil,
		N:            0,
		outSize:      0,
	}
	return hePasta
}

func (pas *HEPastaPack) InitParams(params Parameter, symParams pasta.Parameter) {
	pas.params = params
	pas.symParams = symParams
	pas.outSize = 16
	pas.N = 1 << params.logN
	// create bfvParams from Literal
	fvParams, err := bfv.NewParametersFromLiteral(bfv.ParametersLiteral{
		LogN:             params.logN,
		LogQ:             []int{60, 59, 59, 57, 57, 55, 55, 53, 53, 51, 51, 47, 47},
		LogP:             []int{57, 57, 55, 55, 53, 53, 51, 51, 47, 47},
		PlaintextModulus: params.plainMod,
	})
	pas.logger.HandleError(err)
	pas.bfvParams = fvParams
}

func (pas *HEPastaPack) HEKeyGen() {
	params := pas.bfvParams

	pas.keyGenerator = rlwe.NewKeyGenerator(params)
	pas.sk, pas.pk = pas.keyGenerator.GenKeyPairNew()

	pas.encoder = bfv.NewEncoder(params)
	pas.decryptor = bfv.NewDecryptor(params, pas.sk)
	pas.encryptor = bfv.NewEncryptor(params, pas.pk)

	fmt.Printf("=== Parameters : N=%d, T=%d, LogQP = %f, sigma = %T %v, logMaxSlot= %d \n",
		1<<params.LogN(), params.PlaintextModulus(), params.LogQP(), params.Xe(), params.Xe(), params.LogMaxSlots())
}

func (pas *HEPastaPack) InitFvPasta() MFVPastaPack {
	pas.fvPasta = NEWMFVPastaPack(
		pas.params,
		pas.bfvParams,
		pas.symParams,
		pas.encoder,
		pas.encryptor,
		pas.evaluator)
	return pas.fvPasta
}

func (pas *HEPastaPack) CreateGaloisKeys(dataSize int) {
	pas.rlk = pas.keyGenerator.GenRelinearizationKeyNew(pas.sk)
	galEls := pas.fvPasta.GetGaloisElements(dataSize)
	pas.glk = pas.keyGenerator.GenGaloisKeysNew(galEls, pas.sk)
	pas.evk = rlwe.NewMemEvaluationKeySet(pas.rlk, pas.glk...)
	pas.evaluator = bfv.NewEvaluator(pas.bfvParams, pas.evk)
	pas.fvPasta.UpdateEvaluator(pas.evaluator)
}

// RandomDataGen generates the matrix of random data
// = [output size * number of block]
func (pas *HEPastaPack) RandomDataGen() (data []uint64) {
	size := pas.outSize * pas.N // make it equal as HERA and Rubato
	p := pas.symParams.GetModulus()
	data = make([]uint64, size)
	for i := 0; i < size; i++ {
		data[i] = utils.RandUint64() % p
	}
	return
}

func (pas *HEPastaPack) EncryptSymKey(key HHESoK.Key) {
	pas.symKeyCt = pas.fvPasta.EncKey(key)
	pas.logger.PrintMessages(">> Symmetric Key #slots: ", pas.symKeyCt.Slots())
}

func (pas *HEPastaPack) Trancipher(nonces []byte, dCt []uint64) []*rlwe.Ciphertext {
	tranCipData := pas.fvPasta.Crypt(nonces, pas.symKeyCt, dCt)
	return tranCipData
}

// Decrypt homomorphic ciphertext
func (pas *HEPastaPack) Decrypt(ciphertexts *rlwe.Ciphertext) (res HHESoK.Plaintext) {
	pt := pas.decryptor.DecryptNew(ciphertexts)
	err := pas.encoder.Decode(pt, res)
	pas.logger.HandleError(err)
	return res[:pas.N]
}

func (pas *HEPastaPack) Flatten(ciphers []*rlwe.Ciphertext, dataSize int) (res *rlwe.Ciphertext) {
	ps := pas.symParams.PlainSize
	rem := dataSize % ps
	if rem != 0 {
		// Create a mask slice with 'rem' elements, each initialized to 1.
		mask := make([]uint64, rem)
		for i := range mask {
			mask[i] = 1
		}

		// Apply the mask to the last element of ciphers using the cipher's mask function.
		pas.fvPasta.Mask(ciphers[len(ciphers)-1], mask)
	}
	res = pas.fvPasta.Flatten(ciphers)
	return
}
