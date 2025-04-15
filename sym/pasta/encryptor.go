package pasta

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
	pas pasta
}

// Encrypt plaintext vector
func (enc encryptor) Encrypt(plaintext HHELand.Plaintext) HHELand.Ciphertext {
	logger := utils.NewLogger(utils.DEBUG)
	var size = uint64(len(plaintext))
	var modulus = enc.pas.params.GetModulus()
	var blockSize = uint64(enc.pas.params.GetBlockSize())
	var numBlock = uint64(math.Ceil(float64(size / blockSize)))
	logger.PrintFormatted("Number of Block: %d", numBlock)

	nonce := make([]byte, 8)
	binary.BigEndian.PutUint64(nonce, uint64(123456789))
	counter := make([]byte, 8)

	ciphertext := make(HHELand.Ciphertext, size)
	copy(ciphertext, plaintext)

	for b := uint64(0); b < numBlock; b++ {
		binary.BigEndian.PutUint64(counter, b)
		keyStream := enc.pas.KeyStream(nonce, counter)
		for i := b * blockSize; i < (b+1)*blockSize && i < size; i++ {
			ciphertext[i] = (ciphertext[i] + keyStream[i-b*blockSize]) % modulus
		}
	}

	return ciphertext
}

// Decrypt ciphertext vector
func (enc encryptor) Decrypt(ciphertext HHELand.Ciphertext) HHELand.Plaintext {
	logger := utils.NewLogger(utils.DEBUG)
	var size = uint64(len(ciphertext))
	var modulus = enc.pas.params.GetModulus()
	var blockSize = uint64(enc.pas.params.GetBlockSize())
	var numBlock = uint64(math.Ceil(float64(size / blockSize)))
	logger.PrintFormatted("Number of Block: %d", numBlock)

	plaintext := make(HHELand.Plaintext, size)
	copy(plaintext, ciphertext)

	nonce := make([]byte, 8)
	binary.BigEndian.PutUint64(nonce, uint64(123456789))
	counter := make([]byte, 8)

	for b := uint64(0); b < numBlock; b++ {
		binary.BigEndian.PutUint64(counter, b)
		keyStream := enc.pas.KeyStream(nonce, counter)
		for i := b * blockSize; i < (b+1)*blockSize && i < size; i++ {
			if keyStream[i-b*blockSize] > plaintext[i] {
				plaintext[i] += modulus
			}
			plaintext[i] = plaintext[i] - keyStream[i-b*blockSize]
		}
	}

	return plaintext
}
