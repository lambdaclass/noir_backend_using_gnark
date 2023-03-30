package components

import (
	"fmt"
	"gnark_backend_ffi/backend"
	"math/big"

	fr_bn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

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
