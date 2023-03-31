package plonk_backend

import (
	"fmt"
	"gnark_backend_ffi/backend"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254"
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

func Square(value int, ctx *backend.Context) int {
	var xa, xc int
	var qL, qR, qO, qM1, qM2 constraint.Coeff

	qM1 = ctx.ConstraintSystem.One()
	qM2 = ctx.ConstraintSystem.One()
	xa = value
	xb := value

	qO = ctx.ConstraintSystem.FromInterface(-1)
	var square fr_bn254.Element
	square.Square(&ctx.Variables[value])

	variableName := fmt.Sprintf("(%s^2)", ctx.ConstraintSystem.(*cs_bn254.SparseR1CS).VariableToString(value))
	xc = ctx.AddSecretVariable(variableName, square)

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

// Generates constraints for adding two elliptic curve points.
//
// Generates 7 constraints if the point needs to be checked and 2 constraints if not.
// A point addition result could not be checked as an optimization in the case that
// the resulting point is a partial result of a multiple addition for example.
// The user should take this into account.
//
// augendPointX is the index to the x-coordinate of the augend point in question.
// augendPointY is the index to the y-coordinate of the augend point in question.
// addendPointX is the index to the x-coordinate of the addend point in question.
// addendPointY is the index to the y-coordinate of the addend point in question.
// ctx is the context.
// checkPoint is a flag that will generate additional constraints for checking
// that the resulting point is on the curve.
//
// Returns the indices to the resulting point x and y coordinates.
func AddPoints(augendPointX, augendPointY, addendPointX, addendPointY int, ctx *backend.Context, checkPoint bool) (newPointX, newPointY int) {
	newPointX = add(augendPointX, addendPointX, ctx)
	newPointY = add(augendPointY, addendPointY, ctx)
	if checkPoint {
		AssertPointIsOnCurve(newPointX, newPointY, ctx)
	}
	return
}

// Generates constraints for doubling a point. Doubling a point means adding some
// point to itself.
//
// Generates 7 constraints if the point needs to be checked and 2 constraints if not.
// A point addition result could not be checked as an optimization in the case that
// the resulting point is a partial result of a multiple addition for example.
// The user should take this into account.
//
// x is the index to the x-coordinate of the point in question.
// y is the index to the y-coordinate of the point in question.
// ctx is the context.
// checkPoint is a flag that will generate additional constraints for checking
// that the resulting point is on the curve.
//
// Returns the indices to the resulting point x and y coordinates.
func DoublePoint(x, y int, ctx *backend.Context, checkPoint bool) (doubledX, doubledY int) {
	return AddPoints(x, y, x, y, ctx, checkPoint)
}

// Generates constraints for computing the fixed base scalar multiplication. This
// means multiplying the curve generator with a given scalar.
//
// Generates 5n + 1 constraints where n is the integer value of the scalar.
//
// scalar is the index to the concrete value of the scalar that will multiply
// the curve generator.
// ctx is the context.
func ScalarBaseMul(scalar int, ctx *backend.Context) (resultX, resultY int) {
	switch ctx.ConstraintSystem.(type) {
	case *cs_bn254.SparseR1CS:
		_, _, generator, _ := bn254.Generators()
		x := ctx.AddSecretVariable("genX", fr_bn254.Element(generator.X))
		y := ctx.AddSecretVariable("genY", fr_bn254.Element(generator.Y))
		accumulatorX, accumulatorY := AddPoints(x, y, x, y, ctx, false)
		for i := 0; i < int(ctx.Variables[scalar].Uint64()); i++ {
			accumulatorX, accumulatorY = DoublePoint(x, y, ctx, false)
		}
		AssertPointIsOnCurve(accumulatorX, accumulatorY, ctx)
		resultX = accumulatorX
		resultY = accumulatorY
		return
	}
	return
}
