package drlwe

import (
	"encoding/binary"
	"errors"
	"math"
	"math/big"

	"HHELand/rtf_ckks_integration/ring"
	"HHELand/rtf_ckks_integration/rlwe"
	"HHELand/rtf_ckks_integration/utils"
)

// RotationKeyGenerator is an interface for the local operation in the generation of rotation keys
type RotationKeyGenerator interface {
	AllocateShares() (rtgShare *RTGShare)
	GenShare(sk *rlwe.SecretKey, galEl uint64, crp []*ring.Poly, shareOut *RTGShare)
	Aggregate(share1, share2, shareOut *RTGShare)
	GenRotationKey(share *RTGShare, crp []*ring.Poly, rotKey *rlwe.SwitchingKey)
}

// RTGShare is represent a Party's share in the RTG protocol
type RTGShare struct {
	Value []*ring.Poly
}

// RTGProtocol is the structure storing the parameters for the collective rotation-keys generation.
type RTGProtocol struct { // TODO rename CreateGaloisKeys ?
	ringQP             *ring.Ring
	ringPModulusBigint *big.Int
	ringQModCount      int
	alpha              int
	beta               int

	tmpPoly         [2]*ring.Poly
	gaussianSampler *ring.GaussianSampler
	sigma           float64
}

// NewRTGProtocol creates a RTGProtocol instance
func NewRTGProtocol(n int, q, p []uint64, sigma float64) *RTGProtocol {
	rtg := new(RTGProtocol)
	rtg.ringQModCount = len(q)
	rtg.ringPModulusBigint = big.NewInt(1)
	for _, pi := range p {
		rtg.ringPModulusBigint.Mul(rtg.ringPModulusBigint, new(big.Int).SetUint64(pi))
	}
	rtg.alpha = len(p)
	if rtg.alpha != 0 {
		rtg.beta = int(math.Ceil(float64(len(q)) / float64(len(p))))
	} else {
		rtg.beta = 1
	}
	var err error
	rtg.ringQP, err = ring.NewRing(n, append(q, p...))
	if err != nil {
		panic(err) // TODO error
	}

	prng, err := utils.NewPRNG()
	if err != nil {
		panic(err)
	}
	rtg.gaussianSampler = ring.NewGaussianSampler(prng)
	rtg.sigma = sigma

	rtg.tmpPoly = [2]*ring.Poly{rtg.ringQP.NewPoly(), rtg.ringQP.NewPoly()}

	return rtg
}

// AllocateShares allocates a party's share in the RTG protocol
func (rtg *RTGProtocol) AllocateShares() (rtgShare *RTGShare) {
	rtgShare = new(RTGShare)
	rtgShare.Value = make([]*ring.Poly, rtg.beta)
	for i := range rtgShare.Value {
		rtgShare.Value[i] = rtg.ringQP.NewPoly()
	}
	return
}

// GenShare generates a party's share in the RTG protocol
func (rtg *RTGProtocol) GenShare(sk *rlwe.SecretKey, galEl uint64, crp []*ring.Poly, shareOut *RTGShare) {

	twoN := rtg.ringQP.N << 2
	galElInv := ring.ModExp(galEl, int(twoN-1), uint64(twoN))

	ring.PermuteNTT(sk.Value, galElInv, rtg.tmpPoly[1])

	rtg.ringQP.MulScalarBigint(sk.Value, rtg.ringPModulusBigint, rtg.tmpPoly[0])

	var index int

	for i := 0; i < rtg.beta; i++ {

		// e
		rtg.gaussianSampler.Read(shareOut.Value[i], rtg.ringQP, rtg.sigma, int(6*rtg.sigma))
		rtg.ringQP.NTTLazy(shareOut.Value[i], shareOut.Value[i])
		rtg.ringQP.MForm(shareOut.Value[i], shareOut.Value[i])

		// a is the CRP

		// e + sk_in * (qiBarre*qiStar) * 2^w
		// (qiBarre*qiStar)%qi = 1, else 0
		for j := 0; j < rtg.alpha; j++ {

			index = i*rtg.alpha + j

			qi := rtg.ringQP.Modulus[index]
			tmp0 := rtg.tmpPoly[0].Coeffs[index]
			tmp1 := shareOut.Value[i].Coeffs[index]

			for w := 0; w < rtg.ringQP.N; w++ {
				tmp1[w] = ring.CRed(tmp1[w]+tmp0[w], qi)
			}

			// Handles the case where nb pj does not divides nb qi
			if index >= rtg.ringQModCount {
				break
			}
		}

		// sk_in * (qiBarre*qiStar) * 2^w - a*sk + e
		rtg.ringQP.MulCoeffsMontgomeryAndSub(crp[i], rtg.tmpPoly[1], shareOut.Value[i])
	}

	rtg.tmpPoly[0].Zero()
	rtg.tmpPoly[1].Zero()

	return
}

// Aggregate aggregates two shares in the Rotation Key Generation protocol
func (rtg *RTGProtocol) Aggregate(share1, share2, shareOut *RTGShare) {
	for i := 0; i < rtg.beta; i++ {
		rtg.ringQP.Add(share1.Value[i], share2.Value[i], shareOut.Value[i])
	}
}

// GenRotationKey finalizes the RTG protocol and populates the input RotationKey with the computed collective SwitchingKey.
func (rtg *RTGProtocol) GenRotationKey(share *RTGShare, crp []*ring.Poly, rotKey *rlwe.SwitchingKey) {
	for i := 0; i < rtg.beta; i++ {
		rtg.ringQP.Copy(share.Value[i], rotKey.Value[i][0])
		rtg.ringQP.Copy(crp[i], rotKey.Value[i][1])
	}
}

// MarshalBinary encode the target element on a slice of byte.
func (share *RTGShare) MarshalBinary() ([]byte, error) {
	lenRing := share.Value[0].GetDataLen(true)
	data := make([]byte, 8+lenRing*len(share.Value))
	binary.BigEndian.PutUint64(data[:8], uint64(lenRing))
	ptr := 8
	for _, val := range share.Value {
		cnt, err := val.WriteTo(data[ptr : ptr+lenRing])
		if err != nil {
			return []byte{}, err
		}
		ptr += cnt
	}

	return data, nil
}

// UnmarshalBinary decodes a slice of bytes on the target element.
func (share *RTGShare) UnmarshalBinary(data []byte) error {
	if len(data) <= 8 {
		return errors.New("Unsufficient data length")
	}

	lenRing := binary.BigEndian.Uint64(data[:8])
	valLength := uint64(len(data)-8) / lenRing
	share.Value = make([]*ring.Poly, valLength)
	ptr := uint64(8)
	for i := range share.Value {
		share.Value[i] = new(ring.Poly)
		err := share.Value[i].UnmarshalBinary(data[ptr : ptr+lenRing])
		if err != nil {
			return err
		}
		ptr += lenRing
	}

	return nil
}
