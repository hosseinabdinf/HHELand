package RtF

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"github.com/tuneinsight/lattigo/v6/utils/sampling"

	"HHELand/rtf_integration/ring"
)

// Operand is a common interface for Ciphertext and Plaintext types.
type Operand interface {
	El() *Element
	Degree() int
	Level() int
	Scale() float64
}

// Element is a generic type for ciphertext and plaintexts
type Element struct {
	value []*ring.Poly
	scale float64
	isNTT bool
}

// MarshalBinary encodes the Element struct into a byte slice
func (e *Element) MarshalBinary() ([]byte, error) {
	var buf bytes.Buffer

	// Write the number of *ring.Poly elements
	numPolys := uint64(len(e.value))
	if err := binary.Write(&buf, binary.LittleEndian, numPolys); err != nil {
		return nil, err
	}

	// Write each *ring.Poly as a binary representation
	for _, poly := range e.value {
		data, err := poly.MarshalBinary()
		if err != nil {
			return nil, err
		}

		// Write length of the serialized Poly
		length := uint64(len(data))
		if err := binary.Write(&buf, binary.LittleEndian, length); err != nil {
			return nil, err
		}

		// Write the serialized Poly data
		if _, err := buf.Write(data); err != nil {
			return nil, err
		}
	}

	// Write the scale
	if err := binary.Write(&buf, binary.LittleEndian, e.scale); err != nil {
		return nil, err
	}

	// Write the isNTT flag
	if err := binary.Write(&buf, binary.LittleEndian, e.isNTT); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

// UnmarshalBinary decodes a byte slice into the Element struct
func (e *Element) UnmarshalBinary(data []byte) error {
	buf := bytes.NewReader(data)

	// Read the number of *ring.Poly elements
	var numPolys uint64
	if err := binary.Read(buf, binary.LittleEndian, &numPolys); err != nil {
		return err
	}

	// Read each *ring.Poly
	e.value = make([]*ring.Poly, numPolys)
	for i := uint64(0); i < numPolys; i++ {
		var length uint64
		if err := binary.Read(buf, binary.LittleEndian, &length); err != nil {
			return err
		}

		polyData := make([]byte, length)
		if _, err := buf.Read(polyData); err != nil {
			return err
		}

		poly := new(ring.Poly)
		if err := poly.UnmarshalBinary(polyData); err != nil {
			return err
		}

		e.value[i] = poly
	}

	// Read the scale
	if err := binary.Read(buf, binary.LittleEndian, &e.scale); err != nil {
		return err
	}

	// Read the isNTT flag
	if err := binary.Read(buf, binary.LittleEndian, &e.isNTT); err != nil {
		return err
	}

	return nil
}

// NewElement returns a new Element with zero values.
func NewElement() *Element {
	return &Element{}
}

// Value returns the slice of polynomials of the target element.
func (el *Element) Value() []*ring.Poly {
	return el.value
}

// SetValue sets the input slice of polynomials as the value of the target element.
func (el *Element) SetValue(value []*ring.Poly) {
	el.value = value
}

// Degree returns the degree of the target element.
func (el *Element) Degree() int {
	return len(el.value) - 1
}

// Level returns the level of the target element.
func (el *Element) Level() int {
	return len(el.value[0].Coeffs) - 1
}

// Scale returns the scale of the target element.
func (el *Element) Scale() float64 {
	return el.scale
}

// SetScale sets the scale of the the target element to the input scale.
func (el *Element) SetScale(scale float64) {
	el.scale = scale
}

// MulScale multiplies the scale of the target element with the input scale.
func (el *Element) MulScale(scale float64) {
	el.scale *= scale
}

// DivScale divides the scale of the target element by the input scale.
func (el *Element) DivScale(scale float64) {
	el.scale /= scale
}

// Resize resizes the degree of the target element.
func (el *Element) Resize(params *Parameters, degree int) {
	if el.Degree() > degree {
		el.value = el.value[:degree+1]
	} else if el.Degree() < degree {
		for el.Degree() < degree {
			el.value = append(el.value, []*ring.Poly{new(ring.Poly)}...)
			el.value[el.Degree()].Coeffs = make([][]uint64, el.Level()+1)
			for i := 0; i < el.Level()+1; i++ {
				el.value[el.Degree()].Coeffs[i] = make([]uint64, params.N())
			}
		}
	}
}

// IsNTT returns the value of the NTT flag of the target element.
func (el *Element) IsNTT() bool {
	return el.isNTT
}

// SetIsNTT sets the value of the NTT flag of the target element with the input value.
func (el *Element) SetIsNTT(value bool) {
	el.isNTT = value
}

// NTT puts the target element in the NTT domain and sets its isNTT flag to true. If it is already in the NTT domain, it does nothing.
func (el *Element) NTT(ringQ *ring.Ring, c *Element) {
	if el.Degree() != c.Degree() {
		panic(fmt.Errorf("error: receiver element has invalid degree (it does not match)"))
	}
	if !el.IsNTT() {
		for i := range el.value {
			ringQ.NTTLvl(el.Level(), el.Value()[i], c.Value()[i])
		}
		c.SetIsNTT(true)
	}
}

// InvNTT puts the target element outside of the NTT domain, and sets its isNTT flag to false. If it is not in the NTT domain, it does nothing.
func (el *Element) InvNTT(ringQ *ring.Ring, c *Element) {
	if el.Degree() != c.Degree() {
		panic(fmt.Errorf("error: receiver element invalid degree (it does not match)"))
	}
	if el.IsNTT() {
		for i := range el.value {
			ringQ.InvNTTLvl(el.Level(), el.Value()[i], c.Value()[i])
		}
		c.SetIsNTT(false)
	}
}

// CopyNew creates a new element as a copy of the target element.
func (el *Element) CopyNew() *Element {

	ctxCopy := new(Element)

	ctxCopy.value = make([]*ring.Poly, el.Degree()+1)
	for i := range el.value {
		ctxCopy.value[i] = el.value[i].CopyNew()
	}

	ctxCopy.CopyParams(el)

	return ctxCopy
}

// Copy copies the input element and its parameters on the target element.
func (el *Element) Copy(ctxCopy *Element) {

	if el != ctxCopy {
		for i := range ctxCopy.Value() {
			el.value[i].Copy(ctxCopy.Value()[i])
		}

		el.CopyParams(ctxCopy)
	}
}

// CopyParams copies the input element parameters on the target element
func (el *Element) CopyParams(Element *Element) {
	el.SetScale(Element.Scale())
	el.SetIsNTT(Element.IsNTT())
}

// El sets the target element type to Element.
func (el *Element) El() *Element {
	return el
}

// Ciphertext sets the target element type to Ciphertext.
func (el *Element) Ciphertext() *Ciphertext {
	return &Ciphertext{el}
}

// Plaintext sets the target element type to Plaintext.
func (el *Element) Plaintext() *Plaintext {
	return &Plaintext{el, el.value[0]}
}

func getSmallestLargest(el0, el1 *Element) (smallest, largest *Element, sameDegree bool) {
	switch {
	case el0.Degree() > el1.Degree():
		return el1, el0, false
	case el0.Degree() < el1.Degree():
		return el0, el1, false
	}
	return el0, el1, true
}

func newCiphertextElement(params *Parameters, degree int) *Element {
	el := new(Element)
	el.value = make([]*ring.Poly, degree+1)
	for i := 0; i < degree+1; i++ {
		el.value[i] = ring.NewPoly(params.N(), params.QiCount())
	}
	return el
}

func newPlaintextElement(params *Parameters) *Element {
	el := new(Element)
	el.value = []*ring.Poly{ring.NewPoly(params.N(), params.QiCount())}
	return el
}

func newPlaintextRingTElement(params *Parameters) *Element {
	el := new(Element)
	el.value = []*ring.Poly{ring.NewPoly(params.N(), 1)}
	return el
}

func newPlaintextMulElement(params *Parameters) *Element {
	el := new(Element)
	el.value = []*ring.Poly{ring.NewPoly(params.N(), params.QiCount())}
	return el
}

// NewElementRandom creates a new Element with random coefficients
func populateElementRandom(prng sampling.PRNG, params *Parameters, el *Element) {

	ringQ, err := ring.NewRing(params.N(), params.qi)
	if err != nil {
		panic(err)
	}
	sampler := ring.NewUniformSampler(prng, ringQ)
	for i := range el.value {
		sampler.Read(el.value[i])
	}
}
