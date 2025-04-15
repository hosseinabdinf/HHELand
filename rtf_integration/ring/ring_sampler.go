package ring

import (
	"github.com/tuneinsight/lattigo/v6/utils/sampling"
)

const precision = uint64(56)

type baseSampler struct {
	prng     sampling.PRNG
	baseRing *Ring
}
