package rubato

import (
	"HHELand"
	"HHELand/utils"
	"encoding/binary"
	"math"
)

type Encryptor interface {
	Encrypt(plaintext HHELand.Plaintext) HHELand.Ciphertext
	Decrypt(ciphertext HHELand.Ciphertext) HHELand.Plaintext
}

type encryptor struct {
	rub rubato
}

// Encrypt plaintext vector
func (enc encryptor) Encrypt(plaintext HHELand.Plaintext) HHELand.Ciphertext {
	logger := utils.NewLogger(utils.DEBUG)
	var size = len(plaintext)
	var modulus = enc.rub.params.GetModulus()
	var ksSize = enc.rub.params.GetBlockSize() - 4
	var numBlock = int(math.Ceil(float64(size / ksSize)))
	logger.PrintFormatted("Number of Block: %d", numBlock)

	// Nonce and Counter
	nonces := make([][]byte, numBlock)
	// set nonce up to blockSize
	n := 123456789
	for i := 0; i < numBlock; i++ {
		nonces[i] = make([]byte, 8)
		binary.BigEndian.PutUint64(nonces[i], uint64(i+n))
	}
	counter := make([]byte, 8)

	ciphertext := make(HHELand.Ciphertext, size)
	copy(ciphertext, plaintext)

	for i := 0; i < numBlock; i++ {
		z := make(HHELand.Block, ksSize)
		binary.BigEndian.PutUint64(counter, uint64(i+1))
		copy(z, enc.rub.KeyStream(nonces[i], counter))
		ciphertext[i] = (ciphertext[i] + z[i]) % modulus
	}

	return ciphertext
}

// Decrypt ciphertext vector
func (enc encryptor) Decrypt(ciphertext HHELand.Ciphertext) HHELand.Plaintext {
	logger := utils.NewLogger(utils.DEBUG)
	var size = len(ciphertext)
	var modulus = enc.rub.params.GetModulus()
	var ksSize = enc.rub.params.GetBlockSize() - 4
	var numBlock = int(math.Ceil(float64(size / ksSize)))
	logger.PrintFormatted("Number of Block: %d", numBlock)

	// Nonce and Counter
	nonces := make([][]byte, numBlock)
	// set nonce up to blockSize
	n := 123456789
	for i := 0; i < numBlock; i++ {
		nonces[i] = make([]byte, 8)
		binary.BigEndian.PutUint64(nonces[i], uint64(i+n))
	}
	counter := make([]byte, 8)

	plaintext := make(HHELand.Plaintext, size)
	copy(plaintext, ciphertext)

	for i := 0; i < numBlock; i++ {
		z := make(HHELand.Block, ksSize)
		binary.BigEndian.PutUint64(counter, uint64(i+1))
		copy(z, enc.rub.KeyStream(nonces[i], counter))
		if z[i] > plaintext[i] {
			plaintext[i] += modulus
		}
		plaintext[i] = plaintext[i] - z[i]
	}

	return plaintext
}
