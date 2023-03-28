package plonk_components

import (
	"fmt"
	"math/big"

	fr_bn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	cs_bn254 "github.com/consensys/gnark/constraint/bn254"
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
func toBinaryConversion(felt int, bits int, sparseR1CS *cs_bn254.SparseR1CS, secretVariables fr_bn254.Vector) ([]int, fr_bn254.Vector) {
	/* Felt to binary (hint) */
	var feltConstant big.Int
	secretVariables[felt].BigInt(&feltConstant)

	feltBitsIndices := make([]int, bits)
	for i := 0; i < bits; i++ {
		bigEndianIndex := bits - 1 - i

		bit := fr_bn254.NewElement(uint64(feltConstant.Bit(i)))
		feltBitsIndices[bigEndianIndex] = sparseR1CS.AddSecretVariable(fmt.Sprintf("bit_%d", i))
		assertIsBoolean(feltBitsIndices[bigEndianIndex], sparseR1CS)
		secretVariables = append(secretVariables, bit)
	}

	/* Hint check */
	accumulator := fr_bn254.NewElement(0)
	accumulatorIndex := sparseR1CS.AddSecretVariable("accumulator")
	secretVariables = append(secretVariables, accumulator)

	var c fr_bn254.Element
	coefficientValue := big.NewInt(1)

	// These declarations are needed because if not their reference is lost in the for loop.
	var intermediateProdIndex, cIndex int

	for i := 0; i < bits; i++ {
		c.SetBigInt(coefficientValue)
		cIndex = sparseR1CS.AddSecretVariable(fmt.Sprintf("(2^%d)", i))
		secretVariables = append(secretVariables, c)
		// bits - 1 - i because we want big endian.
		bigEndianIndex := bits - 1 - i
		currentBitIndex := feltBitsIndices[bigEndianIndex]
		intermediateProdIndex, secretVariables = mul(cIndex, currentBitIndex, sparseR1CS, secretVariables)
		accumulatorIndex, secretVariables = add(accumulatorIndex, intermediateProdIndex, sparseR1CS, secretVariables)
		// Shift the coefficient for the next iteration.
		coefficientValue.Lsh(coefficientValue, 1)
	}

	// record the constraint Σ (2**i * b[i]) == a
	assertIsEqual(felt, accumulatorIndex, sparseR1CS)

	return feltBitsIndices, secretVariables
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
func fromBinaryConversion(feltBits []int, sparseR1CS *cs_bn254.SparseR1CS, secretVariables fr_bn254.Vector, unconstrainedInputs bool) (int, fr_bn254.Vector) {
	bits := len(feltBits)
	accumulator := fr_bn254.NewElement(0)
	accumulatorIndex := sparseR1CS.AddSecretVariable("accumulator")
	secretVariables = append(secretVariables, accumulator)

	var c fr_bn254.Element
	coefficientValue := big.NewInt(1)

	// These declarations are needed because if not their reference is lost in the for loop.
	var intermediateProdIndex, cIndex int

	for i := 0; i < bits; i++ {
		c.SetBigInt(coefficientValue)
		cIndex = sparseR1CS.AddSecretVariable(fmt.Sprintf("(2^%d)", i))
		secretVariables = append(secretVariables, c)
		// bits - 1 - i because we want big endian.
		bigEndianIndex := bits - 1 - i
		currentBitIndex := feltBits[bigEndianIndex]
		if unconstrainedInputs {
			assertIsBoolean(currentBitIndex, sparseR1CS)
		}
		intermediateProdIndex, secretVariables = mul(cIndex, currentBitIndex, sparseR1CS, secretVariables)
		accumulatorIndex, secretVariables = add(accumulatorIndex, intermediateProdIndex, sparseR1CS, secretVariables)
		// Shift the coefficient for the next iteration.
		coefficientValue.Lsh(coefficientValue, 1)
	}

	return accumulatorIndex, secretVariables
}
