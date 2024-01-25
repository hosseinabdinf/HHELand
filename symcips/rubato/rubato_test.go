package rubato

import (
	"fmt"
	"reflect"
	"testing"
)

func printLog(msg string) {
	fmt.Printf("\t--- %s\n", msg)
}

func testString(opName string, p Parameter) string {
	return fmt.Sprintf("%s/BlockSize=%d/Modulus=%d/Rounds=%d/Sigma=%f",
		opName, p.GetBlockSize(), p.GetModulus(), p.GetRounds(), p.GetSigma())
}

func TestPasta(t *testing.T) {
	for _, decTest := range decTestVector {
		testDecryption(&decTest, t)
	}
}

func testDecryption(tc *TestContext, t *testing.T) {
	t.Run(testString("Pasta/DecryptionTest", tc.params), func(t *testing.T) {
		rubatoCipher := NewRubato(tc.key, tc.params)
		encryptor := rubatoCipher.NewEncryptor()
		newCiphertext := encryptor.Encrypt(tc.plaintext)
		newPlaintext := encryptor.Decrypt(newCiphertext)

		if reflect.DeepEqual(tc.plaintext, newPlaintext) {
			printLog("Got the same plaintext, it is working fine.")
		} else {
			printLog("The plaintext after DEC is different, decryption failure!")
		}
		if reflect.DeepEqual(tc.expCipherText, newCiphertext) {
			printLog("Got the same ciphertext, it is working fine.")
		} else {
			printLog("The ciphertext after ENC is different, encryption failure!")
		}
	})
}
