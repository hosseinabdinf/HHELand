package RtF

import (
	"math/bits"
)

// PowerOf2 computes op^(2^logPow2), consuming logPow2 levels, and returns the result on opOut. Providing an evaluation
// key is necessary when logPow2 > 1.
func (eval *ckksEvaluator) PowerOf2(op *Ciphertext, logPow2 int, opOut *Ciphertext) {

	if logPow2 == 0 {

		if op != opOut {
			opOut.Copy(op.El())
		}

	} else {

		eval.MulRelin(op.El(), op.El(), opOut)

		if err := eval.Rescale(opOut, eval.scale, opOut); err != nil {
			panic(err)
		}

		for i := 1; i < logPow2; i++ {

			eval.MulRelin(opOut.El(), opOut.El(), opOut)

			if err := eval.Rescale(opOut, eval.scale, opOut); err != nil {
				panic(err)
			}
		}
	}
}

// PowerNew computes op^degree, consuming log(degree) levels, and returns the result on a new element. Providing an evaluation
// key is necessary when degree > 2.
func (eval *ckksEvaluator) PowerNew(op *Ciphertext, degree int) (opOut *Ciphertext) {
	opOut = NewCiphertextCKKS(eval.params, 1, op.Level(), op.Scale())
	eval.Power(op, degree, opOut)
	return
}

// Power computes op^degree, consuming log(degree) levels, and returns the result on opOut. Providing an evaluation
// key is necessary when degree > 2.
func (eval *ckksEvaluator) Power(op *Ciphertext, degree int, opOut *Ciphertext) {

	if degree < 1 {
		panic("eval.Power -> degree cannot be smaller than 1")
	}

	tmpct0 := op.CopyNew()

	var logDegree, po2Degree int

	logDegree = bits.Len64(uint64(degree)) - 1
	po2Degree = 1 << logDegree

	eval.PowerOf2(tmpct0.Ciphertext(), logDegree, opOut)

	degree -= po2Degree

	for degree > 0 {

		logDegree = bits.Len64(uint64(degree)) - 1
		po2Degree = 1 << logDegree

		tmp := NewCiphertextCKKS(eval.params, 1, tmpct0.Level(), tmpct0.Scale())

		eval.PowerOf2(tmpct0.Ciphertext(), logDegree, tmp)

		eval.MulRelin(opOut.El(), tmp.El(), opOut)

		if err := eval.Rescale(opOut, eval.scale, opOut); err != nil {
			panic(err)
		}

		degree -= po2Degree
	}
}

// InverseNew computes 1/op and returns the result on a new element, iterating for n steps and consuming n levels. The algorithm requires the encrypted values to be in the range
// [-1.5 - 1.5i, 1.5 + 1.5i] or the result will be wrong. Each iteration increases the precision.
func (eval *ckksEvaluator) InverseNew(op *Ciphertext, steps int) (opOut *Ciphertext) {

	cbar := eval.NegNew(op)

	eval.AddConst(cbar, 1, cbar)

	tmp := eval.AddConstNew(cbar, 1)
	opOut = tmp.CopyNew().Ciphertext()

	for i := 1; i < steps; i++ {

		eval.MulRelin(cbar.El(), cbar.El(), cbar.Ciphertext())

		if err := eval.Rescale(cbar, eval.scale, cbar); err != nil {
			panic(err)
		}

		tmp = eval.AddConstNew(cbar, 1)

		eval.MulRelin(tmp.El(), opOut.El(), tmp.Ciphertext())

		if err := eval.Rescale(tmp, eval.scale, tmp); err != nil {
			panic(err)
		}

		opOut = tmp.CopyNew().Ciphertext()
	}

	return opOut
}
