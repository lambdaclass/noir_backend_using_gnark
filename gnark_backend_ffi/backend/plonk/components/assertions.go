package components

import (
	"gnark_backend_ffi/backend"

	fr_bn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/constraint"
	cs_bn254 "github.com/consensys/gnark/constraint/bn254"
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

// Generates constraints for asserting that a given value is between 0 and 2^bits
// where the value and the amount of bits are witnesses.
//
// Generates (5 * bits) + 1 constraints.
//
// felt is the index of the evaluated bit in the values vector.
// bits is the index of the value that represents the amount of bits of the
// range in the values vector.
func assertIsInRange(felt, bits int, ctx *backend.Context) {
	feltBits := toBinaryConversion(felt, bits, ctx)
	reconstructedFelt := fromBinaryConversion(feltBits, ctx, false)
	assertIsEqual(felt, reconstructedFelt, ctx.ConstraintSystem)
}

// Generates constraints for asserting that a point is on a curve. The curve
// will depend on the context's constraint system used.
//
// Generates 5 Plonk constraints.
//
// pointX is the index to the x-coordinate of the point in question.
// pointY is the index to the y-coordinate of the point in question.
// ctx is the context.
func AssertPointIsOnCurve(pointX, pointY int, ctx *backend.Context) {
	var left, right int
	switch ctx.ConstraintSystem.(type) {
	case *cs_bn254.SparseR1CS:
		left = Square(pointY, ctx)
		xSquared := Square(pointX, ctx)
		xCubed := mul(xSquared, pointX, ctx)
		// This should be handled as a constant instead of a secret variable. Maybe
		// If we hardcode the constraint this could be avoided.
		curveConstant := ctx.AddSecretVariable("bn254_constant", fr_bn254.NewElement(3))
		right = add(xCubed, curveConstant, ctx)
	}
	assertIsEqual(left, right, ctx.ConstraintSystem)
}
