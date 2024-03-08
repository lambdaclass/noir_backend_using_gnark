package components

import (
	"fmt"
	"gnark_backend_ffi/backend"

	fr_bn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/constraint"
	cs_bn254 "github.com/consensys/gnark/constraint/bn254"
)

// Generates constraints for adding two values.
//
// It generates one Plonk constraint.
//
// augend is the index of the augend in the values vector.
// addend is the index of the addend in the values vector.
// sparseR1CS is the constraint system being mutated.
// secretVariables is the values vector.
//
// Returns a tuple with the index of the result of the operation in the values
// vector and the updated values vector.
func add(augend int, addend int, ctx *backend.Context) int {
	var xa, xb, xc int
	var qL, qR, qO, qM1, qM2 constraint.Coeff

	qL = ctx.ConstraintSystem.One()
	xa = augend
	qR = ctx.ConstraintSystem.One()
	xb = addend
	qO = ctx.ConstraintSystem.FromInterface(-1)
	var sum fr_bn254.Element
	sum.Add(&ctx.Variables[augend], &ctx.Variables[addend])
	// TODO: Remove the interface casting.
	variableName := fmt.Sprintf("(%s+%s)", ctx.ConstraintSystem.(*cs_bn254.SparseR1CS).VariableToString(augend), ctx.ConstraintSystem.(*cs_bn254.SparseR1CS).VariableToString(addend))
	xc = ctx.AddSecretVariable(variableName, sum)

	addConstraint := constraint.SparseR1C{
		L: ctx.ConstraintSystem.MakeTerm(&qL, xa),
		R: ctx.ConstraintSystem.MakeTerm(&qR, xb),
		O: ctx.ConstraintSystem.MakeTerm(&qO, xc),
		M: [2]constraint.Term{ctx.ConstraintSystem.MakeTerm(&qM1, xa), ctx.ConstraintSystem.MakeTerm(&qM2, xb)},
		K: constraint.CoeffIdZero,
	}

	ctx.ConstraintSystem.AddConstraint(addConstraint)

	return xc
}

// Generates constraints for multiplying two values.
//
// It generates one Plonk constraint.
//
// augend is the index of the augend in the values vector.
// addend is the index of the addend in the values vector.
// sparseR1CS is the constraint system being mutated.
// secretVariables is the values vector.
//
// Returns a tuple with the index of the result of the operation in the values
// vector and the updated values vector.
func mul(multiplicand int, multiplier int, ctx *backend.Context) int {
	var xa, xb, xc int
	var qL, qR, qO, qM1, qM2 constraint.Coeff

	qM1 = ctx.ConstraintSystem.One()
	qM2 = ctx.ConstraintSystem.One()
	xa = multiplicand
	xb = multiplier
	qO = ctx.ConstraintSystem.FromInterface(-1)
	var product fr_bn254.Element
	product.Mul(&ctx.Variables[multiplicand], &ctx.Variables[multiplier])
	// TODO: Remove the interface casting.
	variableName := fmt.Sprintf("(%s*%s)", ctx.ConstraintSystem.(*cs_bn254.SparseR1CS).VariableToString(multiplicand), ctx.ConstraintSystem.(*cs_bn254.SparseR1CS).VariableToString(multiplier))
	xc = ctx.AddSecretVariable(variableName, product)

	mulConstraint := constraint.SparseR1C{
		L: ctx.ConstraintSystem.MakeTerm(&qL, xa),
		R: ctx.ConstraintSystem.MakeTerm(&qR, xb),
		O: ctx.ConstraintSystem.MakeTerm(&qO, xc),
		M: [2]constraint.Term{ctx.ConstraintSystem.MakeTerm(&qM1, xa), ctx.ConstraintSystem.MakeTerm(&qM2, xb)},
		K: constraint.CoeffIdZero,
	}

	ctx.ConstraintSystem.AddConstraint(mulConstraint)

	return xc
}

// Generates constraints for subtracting two values.
//
// It generates one Plonk constraint.
//
// minuend is the index of the minuend in the values vector.
// subtrahend is the index of the subtrahend in the values vector.
// sparseR1CS is the constraint system being mutated.
// secretVariables is the values vector.
//
// Returns a tuple with the index of the result of the operation in the values
// vector and the updated values vector.
func sub(minuend int, subtrahend int, ctx *backend.Context) int {
	var xa, xb, xc int
	var qL, qR, qO, qM1, qM2 constraint.Coeff

	qL = ctx.ConstraintSystem.One()
	xa = minuend
	qR = ctx.ConstraintSystem.FromInterface(-1)
	xb = subtrahend
	qO = ctx.ConstraintSystem.FromInterface(-1)
	var difference fr_bn254.Element
	difference.Sub(&ctx.Variables[minuend], &ctx.Variables[subtrahend])
	// TODO: Remove the interface casting.
	variableName := fmt.Sprintf("(%s-%s)", ctx.ConstraintSystem.(*cs_bn254.SparseR1CS).VariableToString(minuend), ctx.ConstraintSystem.(*cs_bn254.SparseR1CS).VariableToString(subtrahend))
	xc = ctx.AddSecretVariable(variableName, difference)

	addConstraint := constraint.SparseR1C{
		L: ctx.ConstraintSystem.MakeTerm(&qL, xa),
		R: ctx.ConstraintSystem.MakeTerm(&qR, xb),
		O: ctx.ConstraintSystem.MakeTerm(&qO, xc),
		M: [2]constraint.Term{ctx.ConstraintSystem.MakeTerm(&qM1, xa), ctx.ConstraintSystem.MakeTerm(&qM2, xb)},
		K: constraint.CoeffIdZero,
	}

	ctx.ConstraintSystem.AddConstraint(addConstraint)

	return xc
}
