package pasta

import (
	"HHELand"
	"HHELand/sym/pasta"
	"encoding/binary"
	"fmt"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"testing"
)

func BenchmarkPasta3Pack(b *testing.B) {
	// comment below loop if you want to go over each testcase manually
	// it helps to get benchmark results when there's memory limit in
	// your test environment
	for _, tc := range pasta3TestVector {
		benchHEPastaPack(tc, b)
	}
	// uncomment following line if you want to use manual test case
	// you can choose test cased from [0-2]
	// benchHEPastaPack(pasta3TestVector[0], b)
}

func BenchmarkPasta4Pack(b *testing.B) {
	// comment below loop if you want to go over each testcase manually
	// it helps to get benchmark results when there's memory limit in
	// your test environment
	for _, tc := range pasta4TestVector {
		benchHEPastaPack(tc, b)
	}
	// uncomment following line if you want to use manual test case
	// you can choose test cased from [0-2]
	// benchHEPastaPack(pasta4TestVector[0], b)
}

func benchHEPastaPack(tc TestContext, b *testing.B) {
	fmt.Println(testString("PASTA", tc.SymParams))
	if testing.Short() {
		b.Skip("skipping benchmark in short mode.")
	}

	logger := HHESoK.NewLogger(HHESoK.DEBUG)
	logger.PrintDataLen(tc.Key)

	hePastaPack := NewHEPastaPack()

	hePastaPack.InitParams(tc.Params, tc.SymParams)

	b.Run("PASTA/HEKeyGen", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			hePastaPack.HEKeyGen()
		}
	})

	_ = hePastaPack.InitFvPasta()

	// generates Random data for full coefficients
	data := hePastaPack.RandomDataGen()

	symPasta := pasta.NewPasta(tc.Key, tc.SymParams)
	var symCipherTexts HHESoK.Ciphertext
	b.Run("PASTA/EncryptSymData", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			symCipherTexts = symPasta.NewEncryptor().Encrypt(data)
		}
	})

	// create Galois keys for evaluation
	b.ResetTimer()
	b.Run("PASTA/GaloisKeysGen", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			hePastaPack.CreateGaloisKeys(len(symCipherTexts))
		}
	})

	// encrypts symmetric master key using BFV on the client side
	b.Run("PASTA/EncryptSymKey", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			hePastaPack.EncryptSymKey(tc.Key)
		}
	})

	nonce := make([]byte, 8)
	binary.BigEndian.PutUint64(nonce, 123456789)

	// the server side tranciphering
	var fvCiphers []*rlwe.Ciphertext
	b.Run("PASTA/Trancipher", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			fvCiphers = hePastaPack.Trancipher(nonce, symCipherTexts)
		}
	})

	var ctRes *rlwe.Ciphertext
	b.Run("PASTA/Flatten", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			ctRes = hePastaPack.Flatten(fvCiphers, len(symCipherTexts))
		}
	})

	//var ptRes HHELand.Plaintext
	b.Run("PASTA/Decrypt", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_ = hePastaPack.Decrypt(ctRes)
		}
	})

}
