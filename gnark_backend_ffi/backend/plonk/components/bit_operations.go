package plonk_components

import (
	fr_bn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/constraint"
	cs_bn254 "github.com/consensys/gnark/constraint/bn254"
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
func and(lhs int, rhs int, sparseR1CS *cs_bn254.SparseR1CS, secretVariables fr_bn254.Vector, unconstrainedInputs bool) (int, fr_bn254.Vector) {
	if unconstrainedInputs {
		assertIsBoolean(lhs, sparseR1CS)
		assertIsBoolean(rhs, sparseR1CS)
	}

	var xa, xb, xc int
	var qL, qR, qO, qM1, qM2 constraint.Coeff

	qM1 = sparseR1CS.One()
	xa = lhs
	qM2 = sparseR1CS.One()
	xb = rhs

	qO = sparseR1CS.FromInterface(-1)
	xc = sparseR1CS.AddSecretVariable("b0 * b1")

	// Add (bit_0 * bit_1) to the values vector so it could be recovered with xc (the index to it).
	var andResult fr_bn254.Element
	andResult.Mul(&secretVariables[lhs], &secretVariables[rhs])
	secretVariables = append(secretVariables, andResult)

	andConstraint := constraint.SparseR1C{
		L: sparseR1CS.MakeTerm(&qL, xa),
		R: sparseR1CS.MakeTerm(&qR, xb),
		O: sparseR1CS.MakeTerm(&qO, xc),
		M: [2]constraint.Term{sparseR1CS.MakeTerm(&qM1, xa), sparseR1CS.MakeTerm(&qM2, xb)},
		K: constraint.CoeffIdZero,
	}

	sparseR1CS.AddConstraint(andConstraint)

	return xc, secretVariables
}

// Generates constraints for the AND operation between to values.
// If you know beforehand that the inputs are boolean, you should use the `and`
// function.
//
// It generates 2 * ((3 * bits) + 1) + bits + (2 * bits) Plonk constraints.
//
// lhs is the index of the left hand side value in the values vector.
// rhs is the index of the right hand side value in the values vector.
// sparseR1CS is the constraint system being mutated.
// secretVariables is the values vector.
//
// Returns a tuple with the index of the result of the AND operation in the values
// vector and the updated values vector.
func And(lhs int, rhs int, bits int, sparseR1CS *cs_bn254.SparseR1CS, secretVariables fr_bn254.Vector) (int, fr_bn254.Vector) {
	lhsBitsIndices, secretVariables := toBinaryConversion(lhs, bits, sparseR1CS, secretVariables)
	rhsBitsIndices, secretVariables := toBinaryConversion(rhs, bits, sparseR1CS, secretVariables)
	resultBits := make([]int, bits)

	for i := 0; i < bits; i++ {
		lhsBitIndex := lhsBitsIndices[i]
		rhsBitIndex := rhsBitsIndices[i]
		// Inputs were constrained in the above `toBinaryConversion` calls.
		resultBit, _secretVariables := and(lhsBitIndex, rhsBitIndex, sparseR1CS, secretVariables, false)
		secretVariables = _secretVariables
		resultBits[i] = resultBit
	}

	return fromBinaryConversion(resultBits, sparseR1CS, secretVariables, false)
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
func xor(lhs int, rhs int, sparseR1CS *cs_bn254.SparseR1CS, secretVariables fr_bn254.Vector, unconstrainedInputs bool) (int, fr_bn254.Vector) {
	if unconstrainedInputs {
		assertIsBoolean(lhs, sparseR1CS)
		assertIsBoolean(rhs, sparseR1CS)
	}

	var xa, xb, xc int
	var qL, qR, qO, qM1, qM2 constraint.Coeff

	// -1 * a
	qL = sparseR1CS.FromInterface(-1)
	xa = lhs
	// -1 * b
	qR = sparseR1CS.FromInterface(-1)
	xb = rhs
	// 2 * (a * b)
	qM1 = sparseR1CS.FromInterface(2)
	xa = lhs
	qM2 = sparseR1CS.One()
	xb = rhs
	// a + b - 2 * a * b
	qO = sparseR1CS.FromInterface(1)
	xc = sparseR1CS.AddSecretVariable("a + b - 2 * (a * b)")

	// Add a + b - 2 * a * b to the values vector so it could be recovered with xc (the index to it).
	var (
		aPlusB          fr_bn254.Element
		aTimesB         fr_bn254.Element
		twoTimesATimesB fr_bn254.Element
		xorResult       fr_bn254.Element
	)
	two := fr_bn254.NewElement(2)
	aPlusB.Add(&secretVariables[lhs], &secretVariables[rhs])
	aTimesB.Mul(&secretVariables[lhs], &secretVariables[rhs])
	twoTimesATimesB.Mul(&two, &aTimesB)
	// a + b - 2 * a * b
	xorResult.Sub(&aPlusB, &twoTimesATimesB)
	secretVariables = append(secretVariables, xorResult)

	andConstraint := constraint.SparseR1C{
		L: sparseR1CS.MakeTerm(&qL, xa),
		R: sparseR1CS.MakeTerm(&qR, xb),
		O: sparseR1CS.MakeTerm(&qO, xc),
		M: [2]constraint.Term{sparseR1CS.MakeTerm(&qM1, xa), sparseR1CS.MakeTerm(&qM2, xb)},
		K: constraint.CoeffIdZero,
	}

	sparseR1CS.AddConstraint(andConstraint)

	return xc, secretVariables
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
// secretVariables is the values vector.
//
// Returns a tuple with the index of the result of the AND operation in the values
// vector and the updated values vector.
func Xor(lhs int, rhs int, bits int, sparseR1CS *cs_bn254.SparseR1CS, secretVariables fr_bn254.Vector) (int, fr_bn254.Vector) {
	lhsBitsIndices, secretVariables := toBinaryConversion(lhs, bits, sparseR1CS, secretVariables)
	rhsBitsIndices, secretVariables := toBinaryConversion(rhs, bits, sparseR1CS, secretVariables)
	resultBits := make([]int, bits)

	for i := 0; i < bits; i++ {
		lhsBitIndex := lhsBitsIndices[i]
		rhsBitIndex := rhsBitsIndices[i]
		// Inputs were constrained in the above `toBinaryConversion` calls.
		resultBit, _secretVariables := xor(lhsBitIndex, rhsBitIndex, sparseR1CS, secretVariables, false)
		secretVariables = _secretVariables
		resultBits[i] = resultBit
	}

	return fromBinaryConversion(resultBits, sparseR1CS, secretVariables, false)
}
