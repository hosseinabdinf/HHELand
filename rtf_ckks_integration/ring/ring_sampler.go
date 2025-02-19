package ring

import (
	"HHELand/rtf_ckks_integration/utils"
)

const precision = uint64(56)

type baseSampler struct {
	prng     utils.PRNG
	baseRing *Ring
}
