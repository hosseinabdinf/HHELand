package RtF

import (
	"HHELand/rtf_integration/ring"
	"github.com/tuneinsight/lattigo/v6/utils/sampling"
	"golang.org/x/crypto/sha3"
)

func PlainRubato(blocksize int, numRound int, nonce []byte, counter []byte, key []uint64, plainModulus uint64, sigma float64) (state []uint64) {
	xof := sha3.NewShake256()
	xof.Write(nonce)
	xof.Write(counter)
	state = make([]uint64, blocksize)

	//prng, err := NewPRNG()
	// Hossein: I used the new Sampling from Lattigo Lib instead of the old one
	prng, err := sampling.NewPRNG()
	if err != nil {
		panic(err)
	}
	gaussianSampler := ring.NewGaussianSampler(prng)

	rks := make([][]uint64, numRound+1)

	for r := 0; r <= numRound; r++ {
		rks[r] = make([]uint64, blocksize)
		for i := 0; i < blocksize; i++ {
			rks[r][i] = SampleZqx(xof, plainModulus) * key[i] % plainModulus
		}
	}

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
