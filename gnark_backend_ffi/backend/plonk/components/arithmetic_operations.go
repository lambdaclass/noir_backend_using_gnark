package plonk_components

import (
	"fmt"

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
func add(augend int, addend int, sparseR1CS constraint.SparseR1CS, variables fr_bn254.Vector) (int, fr_bn254.Vector, fr_bn254.Vector) {
	var xa, xb, xc int
	var qL, qR, qO, qM1, qM2 constraint.Coeff

	qL = sparseR1CS.One()
	xa = augend
	qR = sparseR1CS.One()
	xb = addend
	qO = sparseR1CS.FromInterface(-1)
	// TODO: Remove the interface casting.
	xc = sparseR1CS.AddSecretVariable(fmt.Sprintf("(%s+%s)", sparseR1CS.(*cs_bn254.SparseR1CS).VariableToString(augend), sparseR1CS.(*cs_bn254.SparseR1CS).VariableToString(addend)))

	var sum fr_bn254.Element
	sum.Add(&variables[augend], &variables[addend])
	addedSecretVariables := fr_bn254.Vector{sum}
	variables = append(variables, sum)

	addConstraint := constraint.SparseR1C{
		L: sparseR1CS.MakeTerm(&qL, xa),
		R: sparseR1CS.MakeTerm(&qR, xb),
		O: sparseR1CS.MakeTerm(&qO, xc),
		M: [2]constraint.Term{sparseR1CS.MakeTerm(&qM1, xa), sparseR1CS.MakeTerm(&qM2, xb)},
		K: constraint.CoeffIdZero,
	}

	sparseR1CS.AddConstraint(addConstraint)

	return xc, addedSecretVariables, variables
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
func mul(multiplicand int, multiplier int, sparseR1CS constraint.SparseR1CS, variables fr_bn254.Vector) (int, fr_bn254.Vector, fr_bn254.Vector) {
	var xa, xb, xc int
	var qL, qR, qO, qM1, qM2 constraint.Coeff

	qM1 = sparseR1CS.One()
	qM2 = sparseR1CS.One()
	xa = multiplicand
	xb = multiplier
	qO = sparseR1CS.FromInterface(-1)
	// TODO: Remove the interface casting.
	xc = sparseR1CS.AddSecretVariable(fmt.Sprintf("(%s*%s)", sparseR1CS.(*cs_bn254.SparseR1CS).VariableToString(multiplicand), sparseR1CS.(*cs_bn254.SparseR1CS).VariableToString(multiplier)))

	var product fr_bn254.Element
	product.Mul(&variables[multiplicand], &variables[multiplier])
	addedSecretVariables := fr_bn254.Vector{product}
	variables = append(variables, product)

	mulConstraint := constraint.SparseR1C{
		L: sparseR1CS.MakeTerm(&qL, xa),
		R: sparseR1CS.MakeTerm(&qR, xb),
		O: sparseR1CS.MakeTerm(&qO, xc),
		M: [2]constraint.Term{sparseR1CS.MakeTerm(&qM1, xa), sparseR1CS.MakeTerm(&qM2, xb)},
		K: constraint.CoeffIdZero,
	}

	sparseR1CS.AddConstraint(mulConstraint)

	return xc, addedSecretVariables, variables
}
