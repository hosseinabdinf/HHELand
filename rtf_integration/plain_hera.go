package RtF

import "golang.org/x/crypto/sha3"

func PlainHera(roundNum int, nonce []byte, key []uint64, plainModulus uint64) (state []uint64) {
	nr := roundNum
	xof := sha3.NewShake256()
	xof.Write(nonce)
	state = make([]uint64, 16)

	rks := make([][]uint64, nr+1)

	for r := 0; r <= nr; r++ {
		rks[r] = make([]uint64, 16)
		for st := 0; st < 16; st++ {
			rks[r][st] = SampleZqx(xof, plainModulus) * key[st] % plainModulus
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
