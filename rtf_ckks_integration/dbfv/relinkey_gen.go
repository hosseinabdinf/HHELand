package dbfv

import (
	"HHELand/rtf_ckks_integration/bfv"
	"HHELand/rtf_ckks_integration/drlwe"
)

// RKGProtocol is the structure storing the parameters and state for a party in the collective relinearization key
// generation protocol.
type RKGProtocol struct {
	drlwe.RKGProtocol
}

// NewRKGProtocol creates a new RKGProtocol object that will be used to generate a collective evaluation-key
// among j parties in the given context with the given bit-decomposition.
func NewRKGProtocol(params *bfv.Parameters) *RKGProtocol {
	return &RKGProtocol{*drlwe.NewRKGProtocol(params.N(), params.Qi(), params.Pi(), 0.5, params.Sigma())}
}

// GenBFVRelinearizationKey finalizes the protocol and returns the common EvaluationKey.
func (ekg *RKGProtocol) GenBFVRelinearizationKey(round1 *drlwe.RKGShare, round2 *drlwe.RKGShare, evalKeyOut *bfv.RelinearizationKey) {
	ekg.GenRelinearizationKey(round1, round2, &evalKeyOut.RelinearizationKey)
}
