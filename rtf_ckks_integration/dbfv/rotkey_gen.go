package dbfv

import (
	"HHELand/rtf_ckks_integration/bfv"
	"HHELand/rtf_ckks_integration/drlwe"
	"HHELand/rtf_ckks_integration/ring"
)

// RTGProtocol is the structure storing the parameters for the collective rotation-keys generation.
type RTGProtocol struct {
	drlwe.RTGProtocol
}

// NewRotKGProtocol creates a new rotkg object and will be used to generate collective rotation-keys from a shared secret-key among j parties.
func NewRotKGProtocol(params *bfv.Parameters) (rtg *RTGProtocol) {
	return &RTGProtocol{*drlwe.NewRTGProtocol(params.N(), params.Qi(), params.Pi(), params.Sigma())}
}

// GenBFVRotationKey populates the input RotationKeys struture with the Switching key computed from the protocol.
func (rtg *RTGProtocol) GenBFVRotationKey(share *drlwe.RTGShare, crp []*ring.Poly, rotKey *bfv.SwitchingKey) {
	rtg.GenRotationKey(share, crp, &rotKey.SwitchingKey)
}
