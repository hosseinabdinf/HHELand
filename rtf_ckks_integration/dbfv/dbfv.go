package dbfv

import (
	"HHELand/rtf_ckks_integration/bfv"
	"HHELand/rtf_ckks_integration/ring"
)

type dbfvContext struct {
	params *bfv.Parameters

	// Polynomial degree
	n int

	// floor(Q/T) mod each Qi in Montgomery form
	deltaMont []uint64

	// Polynomial contexts
	ringT  *ring.Ring
	ringQ  *ring.Ring
	ringP  *ring.Ring
	ringQP *ring.Ring
}

func newDbfvContext(params *bfv.Parameters) *dbfvContext {

	n := params.N()

	ringT, err := ring.NewRing(n, []uint64{params.T()})
	if err != nil {
		panic(err)
	}

	ringQ, err := ring.NewRing(n, params.Qi())
	if err != nil {
		panic(err)
	}

	ringP, err := ring.NewRing(n, params.Pi())
	if err != nil {
		panic(err)
	}

	ringQP, err := ring.NewRing(n, append(params.Qi(), params.Pi()...))
	if err != nil {
		panic(err)
	}

	deltaMont := bfv.GenLiftParams(ringQ, params.T())

	return &dbfvContext{
		params:    params.Copy(),
		n:         n,
		deltaMont: deltaMont,
		ringT:     ringT,
		ringQ:     ringQ,
		ringP:     ringP,
		ringQP:    ringQP,
	}
}
