package plonk_backend

import (
	"fmt"
	"gnark_backend_ffi/backend"
	"math/big"

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

// Generates constraints for converting a value into its binary representation.
// We use a hint which converts the value into its binary representation outside
// of the circuit and then we check that the result of the conversion is correct.
// TODO: Use this hint with the Hints API
//
// It generates (3 * bits) + 1 Plonk constraints.
//
// felt is the index of the value to convert in the values vector.
// bits is the number of bits to use for the conversion.
// sparseR1CS is the constraint system being mutated.
// secretVariables is the values vector.
//
// Returns a tuple with the indices of the bits in the values vector (big-endian)
// and the updated values vector.
func toBinaryConversion(felt int, bits int, ctx *backend.Context) []int {
	/* Felt to binary (hint) */
	var feltConstant big.Int
	ctx.Variables[felt].BigInt(&feltConstant)

	resultIndices := make([]int, bits)
	for i := 0; i < bits; i++ {
		bigEndianIndex := bits - 1 - i
		bit := fr_bn254.NewElement(uint64(feltConstant.Bit(i)))
		resultIndices[bigEndianIndex] = ctx.AddSecretVariable(fmt.Sprintf("bit_%d", i), bit)
		assertIsBoolean(resultIndices[bigEndianIndex], ctx.ConstraintSystem)
	}

	/* Hint check */
	accumulator := fr_bn254.NewElement(0)
	accumulatorIndex := ctx.AddSecretVariable("accumulator", accumulator)

	var c fr_bn254.Element
	coefficientValue := big.NewInt(1)

	// These declarations are needed because if not their reference is lost in the for loop.
	var intermediateProdIndex, cIndex int

	for i := 0; i < bits; i++ {
		c.SetBigInt(coefficientValue)
		cIndex = ctx.AddSecretVariable(fmt.Sprintf("(2^%d)", i), c)
		// bits - 1 - i because we want big endian.
		bigEndianIndex := bits - 1 - i
		currentBitIndex := resultIndices[bigEndianIndex]
		intermediateProdIndex = mul(cIndex, currentBitIndex, ctx)
		accumulatorIndex = add(accumulatorIndex, intermediateProdIndex, ctx)
		// Shift the coefficient for the next iteration.
		coefficientValue.Lsh(coefficientValue, 1)
	}

	// record the constraint Σ (2**i * b[i]) == a
	assertIsEqual(felt, accumulatorIndex, ctx.ConstraintSystem)

	return resultIndices
}

// Generates constraints for converting some bits into a value.
//
// It generates (2 * bits) Plonk constraints with constrained inputs or
// (3 * bits) Plonk constraints with unconstrained inputs.
//
// feltBits is the indices of the bits in the values vector (big-endian).
// sparseR1CS is the constraint system being mutated.
// secretVariables is the values vector.
// unconstrainedInputs is a boolean that indicates if the inputs are constrained
// or not. If they are not constrained, then the function will generate the
// necessary constraints to ensure that the inputs are boolean.
//
// Returns a tuple with the index of the result of the conversion in the values
// vector and the updated values vector.
func fromBinaryConversion(feltBits []int, ctx *backend.Context, unconstrainedInputs bool) int {
	bits := len(feltBits)
	accumulator := fr_bn254.NewElement(0)
	accumulatorIndex := ctx.AddSecretVariable("accumulator", accumulator)

	var c fr_bn254.Element
	coefficientValue := big.NewInt(1)

	// These declarations are needed because if not their reference is lost in the for loop.
	var intermediateProdIndex, cIndex int

	for i := 0; i < bits; i++ {
		c.SetBigInt(coefficientValue)
		cIndex = ctx.AddSecretVariable(fmt.Sprintf("(2^%d)", i), c)
		// bits - 1 - i because we want big endian.
		bigEndianIndex := bits - 1 - i
		currentBitIndex := feltBits[bigEndianIndex]
		if unconstrainedInputs {
			assertIsBoolean(currentBitIndex, ctx.ConstraintSystem)
		}
		intermediateProdIndex = mul(cIndex, currentBitIndex, ctx)
		accumulatorIndex = add(accumulatorIndex, intermediateProdIndex, ctx)
		// Shift the coefficient for the next iteration.
		coefficientValue.Lsh(coefficientValue, 1)
	}

	return accumulatorIndex
}

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

// (trueValue - falseValue) * condition + falseValue
// If condition = 0 => (trueValue - falseValue) * 0 + falseValue = falseValue
// If condition = 0 => (trueValue - falseValue) * 1 + falseValue = trueValue
func Select(condition, trueValue, falseValue int, ctx *backend.Context, unconstrainedCondition bool) int {
	if unconstrainedCondition {
		assertIsBoolean(condition, ctx.ConstraintSystem)
	}
	trueValueMinusFalseValue := sub(trueValue, falseValue, ctx)
	trueValueMinusFalseValueTimesCondition := mul(trueValueMinusFalseValue, condition, ctx)
	return add(trueValueMinusFalseValueTimesCondition, falseValue, ctx)
}
