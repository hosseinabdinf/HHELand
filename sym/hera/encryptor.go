package hera

import (
	"HHELand"
	"HHELand/utils"
	"encoding/binary"
	"math"
)

type Encryptor interface {
	Encrypt(plaintext HHELand.Plaintext) HHELand.Ciphertext
	Decrypt(ciphertext HHELand.Ciphertext) HHELand.Plaintext
	KeyStream(size int) HHELand.Matrix
}

type encryptor struct {
	her hera
}

// Encrypt plaintext
func (enc encryptor) Encrypt(plaintext HHELand.Plaintext) HHELand.Ciphertext {
	logger := utils.NewLogger(utils.DEBUG)
	var size = len(plaintext)
	var modulus = enc.her.params.GetModulus()
	var blockSize = enc.her.params.GetBlockSize()
	var numBlock = int(math.Ceil(float64(size / blockSize)))
	logger.PrintFormatted("Number of Block: %d", numBlock)

	// Nonce and Counter
	nonces := make([][]byte, numBlock)
	// set nonce up to blockSize
	n := 123456789
	for i := 0; i < numBlock; i++ {
		nonces[i] = make([]byte, 8)
		binary.BigEndian.PutUint64(nonces[i], uint64(i+n))
	}

	ciphertext := make(HHELand.Ciphertext, size)
	copy(ciphertext, plaintext)

	for i := 0; i < numBlock; i++ {
		z := make(HHELand.Block, blockSize)
		copy(z, enc.her.KeyStream(nonces[i]))
		ciphertext[i] = (ciphertext[i] + z[i]) % modulus
	}

	return ciphertext
}

// Decrypt ciphertext
func (enc encryptor) Decrypt(ciphertext HHELand.Ciphertext) HHELand.Plaintext {
	logger := utils.NewLogger(utils.DEBUG)

	var size = len(ciphertext)
	var modulus = enc.her.params.GetModulus()
	var blockSize = enc.her.params.GetBlockSize()
	var numBlock = int(math.Ceil(float64(size / blockSize)))
	logger.PrintFormatted("Number of Block: %d", numBlock)

	// Nonce and Counter
	nonces := make([][]byte, numBlock)
	// set nonce up to blockSize
	n := 123456789
	for i := 0; i < numBlock; i++ {
		nonces[i] = make([]byte, 8)
		binary.BigEndian.PutUint64(nonces[i], uint64(i+n))
	}

	plaintext := make(HHELand.Plaintext, size)
	copy(plaintext, ciphertext)

	for i := 0; i < numBlock; i++ {
		z := make(HHELand.Block, blockSize)
		copy(z, enc.her.KeyStream(nonces[i]))

		if z[i] > plaintext[i] {
			plaintext[i] += modulus
		}
		plaintext[i] = plaintext[i] - z[i]
	}

	return plaintext
}

// KeyStream takes len(plaintext) as input and generate a KeyStream
func (enc encryptor) KeyStream(size int) (keyStream HHELand.Matrix) {
	logger := utils.NewLogger(utils.DEBUG)

	blockSize := enc.her.params.GetBlockSize()
	numBlock := int(math.Ceil(float64(size / blockSize)))
	logger.PrintFormatted("Number of Block: %d", numBlock)

	nonces := make([][]byte, numBlock)
	// set nonce up to blockSize
	n := 123456789
	for i := 0; i < numBlock; i++ {
		nonces[i] = make([]byte, 8)
		binary.BigEndian.PutUint64(nonces[i], uint64(i+n))
	}

	// generate key stream
	keyStream = make(HHELand.Matrix, numBlock)
	for i := 0; i < numBlock; i++ {
		copy(keyStream[i], enc.her.KeyStream(nonces[i]))
	}

	return
}
