package components

import (
	"github.com/consensys/gnark/constraint"
)

// Generates constraints for asserting that a given value is boolean.
//
// bitIndex is the index of the evaluated bit in the values vector.
// sparseR1CS is the constraint system being mutated.
// secretVariables is the vector of secret variables and it is necessary because
// we're adding two new values here (one for 1 - b and another one for (1 - b) * b)
// and they could not be public because they're intermediate variables and they
// could not be internal variables because in that case we'd lose track of the
// index of these added variables.
func assertIsBoolean(bitIndex int, sparseR1CS constraint.SparseR1CS) {
	var xa, xb, xc int
	var qL, qR, qO, qM1, qM2 constraint.Coeff

	// -bit + 1 * (bit * bit) = 0
	qL = sparseR1CS.FromInterface(-1)
	xa = bitIndex
	xb = bitIndex
	qM1 = sparseR1CS.One()
	qM2 = sparseR1CS.One()

	constraint := constraint.SparseR1C{
		L: sparseR1CS.MakeTerm(&qL, xa),
		R: sparseR1CS.MakeTerm(&qR, xb),
		O: sparseR1CS.MakeTerm(&qO, xc),
		M: [2]constraint.Term{sparseR1CS.MakeTerm(&qM1, xa), sparseR1CS.MakeTerm(&qM2, xb)},
		K: constraint.CoeffIdZero,
	}

	sparseR1CS.AddConstraint(constraint)
}

// Generates constraints for asserting that two given values are equal.
//
// bitIndex is the index of the evaluated bit in the values vector.
// sparseR1CS is the constraint system being mutated.
// secretVariables is the values vector.
func assertIsEqual(lhs int, rhs int, sparseR1CS constraint.SparseR1CS) {
	var xa, xb, xc int
	var qL, qR, qO, qM1, qM2 constraint.Coeff

	// lhs - rhs = 0
	qL = sparseR1CS.One()
	xa = lhs
	qR = sparseR1CS.FromInterface(-1)
	xb = rhs

	constraint := constraint.SparseR1C{
		L: sparseR1CS.MakeTerm(&qL, xa),
		R: sparseR1CS.MakeTerm(&qR, xb),
		O: sparseR1CS.MakeTerm(&qO, xc),
		M: [2]constraint.Term{sparseR1CS.MakeTerm(&qM1, xa), sparseR1CS.MakeTerm(&qM2, xb)},
		K: constraint.CoeffIdZero,
	}

	sparseR1CS.AddConstraint(constraint)
}
