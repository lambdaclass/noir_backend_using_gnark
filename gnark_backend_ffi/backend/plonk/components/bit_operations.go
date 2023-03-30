package components

import (
	"gnark_backend_ffi/backend"

	fr_bn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/constraint"
)

// Generates constraints for the bit operation AND between two boolean values.
//
// It generates one Plonk constraint with constrained inputs or three Plonk
// constraint with unconstrained inputs.
//
// lhs is the index of the left hand side of the AND operation in the values vector.
// rhs is the index of the right hand side of the AND operation in the values vector.
// sparseR1CS is the constraint system being mutated.
// unconstrainedInputs is a boolean that indicates if the inputs are constrained
// or not. If they are not constrained, then the function will generate the
// necessary constraints to ensure that the inputs are boolean.
//
// Returns a tuple with the index of the result of the operation in the secret
// variables vector.
func and(lhs int, rhs int, ctx *backend.Context, unconstrainedInputs bool) int {
	if unconstrainedInputs {
		assertIsBoolean(lhs, ctx.ConstraintSystem)
		assertIsBoolean(rhs, ctx.ConstraintSystem)
	}

	var xa, xb, xc int
	var qL, qR, qO, qM1, qM2 constraint.Coeff

	qM1 = ctx.ConstraintSystem.One()
	xa = lhs
	qM2 = ctx.ConstraintSystem.One()
	xb = rhs

	qO = ctx.ConstraintSystem.FromInterface(-1)
	// Add (bit_0 * bit_1) to the values vector so it could be recovered with xc (the index to it).
	var andResult fr_bn254.Element
	andResult.Mul(&ctx.Variables[lhs], &ctx.Variables[rhs])
	xc = ctx.AddSecretVariable("b0 * b1", andResult)

	andConstraint := constraint.SparseR1C{
		L: ctx.ConstraintSystem.MakeTerm(&qL, xa),
		R: ctx.ConstraintSystem.MakeTerm(&qR, xb),
		O: ctx.ConstraintSystem.MakeTerm(&qO, xc),
		M: [2]constraint.Term{ctx.ConstraintSystem.MakeTerm(&qM1, xa), ctx.ConstraintSystem.MakeTerm(&qM2, xb)},
		K: constraint.CoeffIdZero,
	}

	ctx.ConstraintSystem.AddConstraint(andConstraint)

	return xc
}

// Generates constraints for the AND operation between to values.
// If you know beforehand that the inputs are boolean, you should use the `and`
// component.
//
// It generates 2 * ((3 * bits) + 1) + bits + (2 * bits) Plonk constraints.
//
// lhs is the index of the left hand side value in the values vector.
// rhs is the index of the right hand side value in the values vector.
// sparseR1CS is the constraint system being mutated.
// variables is the values vector.
//
// Returns a tuple with the index of the result of the AND operation in the values
// vector and the updated values vector.
func And(lhs int, rhs int, bits int, ctx *backend.Context) int {
	lhsBitsIndices := toBinaryConversion(lhs, bits, ctx)
	rhsBitsIndices := toBinaryConversion(rhs, bits, ctx)
	resultBits := make([]int, bits)

	for i := 0; i < bits; i++ {
		lhsBitIndex := lhsBitsIndices[i]
		rhsBitIndex := rhsBitsIndices[i]
		// Inputs were constrained in the above `toBinaryConversion` calls.
		resultBit := and(lhsBitIndex, rhsBitIndex, ctx, false)
		resultBits[i] = resultBit
	}

	resultIndex := fromBinaryConversion(resultBits, ctx, false)

	return resultIndex
}

// Generates constraints for the bit operation XOR between two boolean values.
//
// It generates one Plonk constraint with constrained inputs or three Plonk
// constraint with unconstrained inputs.
//
// lhs is the index of the left hand side of the XOR operation in the values vector.
// rhs is the index of the right hand side of the XOR operation in the values vector.
// sparseR1CS is the constraint system being mutated.
// unconstrainedInputs is a boolean that indicates if the inputs are constrained
// or not. If they are not constrained, then the function will generate the
// necessary constraints to ensure that the inputs are boolean.
//
// Returns a tuple with the index of the result of the operation in the secret
// variables vector.
func xor(lhs int, rhs int, ctx *backend.Context, unconstrainedInputs bool) int {
	if unconstrainedInputs {
		assertIsBoolean(lhs, ctx.ConstraintSystem)
		assertIsBoolean(rhs, ctx.ConstraintSystem)
	}

	var xa, xb, xc int
	var qL, qR, qO, qM1, qM2 constraint.Coeff

	// -1 * a
	qL = ctx.ConstraintSystem.FromInterface(-1)
	xa = lhs
	// -1 * b
	qR = ctx.ConstraintSystem.FromInterface(-1)
	xb = rhs
	// 2 * (a * b)
	qM1 = ctx.ConstraintSystem.FromInterface(2)
	xa = lhs
	qM2 = ctx.ConstraintSystem.One()
	xb = rhs
	// a + b - 2 * a * b
	qO = ctx.ConstraintSystem.FromInterface(1)
	// Add a + b - 2 * a * b to the values vector so it could be recovered with xc (the index to it).
	var (
		aPlusB          fr_bn254.Element
		aTimesB         fr_bn254.Element
		twoTimesATimesB fr_bn254.Element
		xorResult       fr_bn254.Element
	)
	two := fr_bn254.NewElement(2)
	aPlusB.Add(&ctx.Variables[lhs], &ctx.Variables[rhs])
	aTimesB.Mul(&ctx.Variables[lhs], &ctx.Variables[rhs])
	twoTimesATimesB.Mul(&two, &aTimesB)
	// a + b - 2 * a * b
	xorResult.Sub(&aPlusB, &twoTimesATimesB)
	xc = ctx.AddSecretVariable("a + b - 2 * (a * b)", xorResult)

	andConstraint := constraint.SparseR1C{
		L: ctx.ConstraintSystem.MakeTerm(&qL, xa),
		R: ctx.ConstraintSystem.MakeTerm(&qR, xb),
		O: ctx.ConstraintSystem.MakeTerm(&qO, xc),
		M: [2]constraint.Term{ctx.ConstraintSystem.MakeTerm(&qM1, xa), ctx.ConstraintSystem.MakeTerm(&qM2, xb)},
		K: constraint.CoeffIdZero,
	}

	ctx.ConstraintSystem.AddConstraint(andConstraint)

	return xc
}

// Generates constraints for the XOR operation between to values.
// If you know beforehand that the inputs are boolean, you should use the `xor`
// component.
//
// It generates 2 * ((3 * bits) + 1) + bits + (2 * bits) Plonk constraints.
//
// lhs is the index of the left hand side value in the values vector.
// rhs is the index of the right hand side value in the values vector.
// sparseR1CS is the constraint system being mutated.
// variables is the values vector.
//
// Returns a tuple with the index of the result of the AND operation in the values
// vector and the updated values vector.
func Xor(lhs int, rhs int, bits int, ctx *backend.Context) int {
	lhsBitsIndices := toBinaryConversion(lhs, bits, ctx)
	rhsBitsIndices := toBinaryConversion(rhs, bits, ctx)
	resultBits := make([]int, bits)

	for i := 0; i < bits; i++ {
		lhsBitIndex := lhsBitsIndices[i]
		rhsBitIndex := rhsBitsIndices[i]
		// Inputs were constrained in the above `toBinaryConversion` calls.
		resultBit := xor(lhsBitIndex, rhsBitIndex, ctx, false)
		resultBits[i] = resultBit
	}

	resultIndex := fromBinaryConversion(resultBits, ctx, false)

	return resultIndex
}
