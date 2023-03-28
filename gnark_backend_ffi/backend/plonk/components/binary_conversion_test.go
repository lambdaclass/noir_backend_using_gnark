package plonk_components

import (
	"gnark_backend_ffi/backend"
	"testing"

	fr_bn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	cs_bn254 "github.com/consensys/gnark/constraint/bn254"
	"github.com/stretchr/testify/assert"
)

func TestToBinaryConversionWithNoBits(t *testing.T) {
	values := fr_bn254.Vector{fr_bn254.One()}
	sparseR1CS := cs_bn254.NewSparseR1CS(1)

	publicVariables, secretVariables, variables, _ := backend.HandleValues(sparseR1CS, values, []uint32{})

	result, addedSecretVariables, variables := toBinaryConversion(0, 0, sparseR1CS, variables)
	assert.Empty(t, result)

	secretVariables = append(secretVariables, addedSecretVariables...)
	assertThatProvingFails(t, publicVariables, secretVariables, sparseR1CS)
}

func TestToBinaryConversionWithOneBit(t *testing.T) {
	values := fr_bn254.Vector{fr_bn254.One()}
	sparseR1CS := cs_bn254.NewSparseR1CS(1)

	publicVariables, secretVariables, variables, _ := backend.HandleValues(sparseR1CS, values, []uint32{})

	result, addedSecretVariables, variables := toBinaryConversion(0, 1, sparseR1CS, variables)
	assert.Equal(t, fr_bn254.One(), variables[result[0]])

	secretVariables = append(secretVariables, addedSecretVariables...)
	assertThatProvingAndVerifyingSucceeds(t, publicVariables, secretVariables, sparseR1CS)
}

func TestToBinaryConversionWithMoreThanOneBit(t *testing.T) {
	values := fr_bn254.Vector{fr_bn254.NewElement(3)}
	sparseR1CS := cs_bn254.NewSparseR1CS(1)

	publicVariables, secretVariables, variables, _ := backend.HandleValues(sparseR1CS, values, []uint32{})

	result, addedSecretVariables, variables := toBinaryConversion(0, 2, sparseR1CS, variables)
	assert.Equal(t, fr_bn254.One(), variables[result[0]])
	assert.Equal(t, fr_bn254.One(), variables[result[1]])

	secretVariables = append(secretVariables, addedSecretVariables...)
	assertThatProvingAndVerifyingSucceeds(t, publicVariables, secretVariables, sparseR1CS)
}

func TestFromBinaryConversionWithOneBit(t *testing.T) {
	one := fr_bn254.One()
	values := fr_bn254.Vector{one}
	sparseR1CS := cs_bn254.NewSparseR1CS(1)
	var addedSecretVariables fr_bn254.Vector

	publicVariables, secretVariables, variables, _ := backend.HandleValues(sparseR1CS, values, []uint32{})

	binaryResult, _addedSecretVariables, variables := toBinaryConversion(0, 1, sparseR1CS, variables)
	addedSecretVariables = append(addedSecretVariables, _addedSecretVariables...)
	result, _addedSecretVariables, variables := fromBinaryConversion(binaryResult, sparseR1CS, variables, false)
	addedSecretVariables = append(addedSecretVariables, _addedSecretVariables...)
	assert.Equal(t, one, variables[result])

	secretVariables = append(secretVariables, addedSecretVariables...)
	assertThatProvingAndVerifyingSucceeds(t, publicVariables, secretVariables, sparseR1CS)
}

func TestFromBinaryConversionWithMoreThanOneBit(t *testing.T) {
	three := fr_bn254.NewElement(3)
	values := fr_bn254.Vector{three}
	sparseR1CS := cs_bn254.NewSparseR1CS(1)
	var addedSecretVariables fr_bn254.Vector

	publicVariables, secretVariables, variables, _ := backend.HandleValues(sparseR1CS, values, []uint32{})

	binaryResult, _addedSecretVariables, variables := toBinaryConversion(0, 2, sparseR1CS, variables)
	addedSecretVariables = append(addedSecretVariables, _addedSecretVariables...)
	result, _addedSecretVariables, variables := fromBinaryConversion(binaryResult, sparseR1CS, variables, false)
	addedSecretVariables = append(addedSecretVariables, _addedSecretVariables...)
	assert.Equal(t, three, variables[result])

	secretVariables = append(secretVariables, addedSecretVariables...)
	assertThatProvingAndVerifyingSucceeds(t, publicVariables, secretVariables, sparseR1CS)
}

func TestFromBinaryConversionWithUnconstrainedInputs(t *testing.T) {
	one := fr_bn254.One()
	zero := fr_bn254.NewElement(0)
	values := fr_bn254.Vector{one, one, zero}
	sparseR1CS := cs_bn254.NewSparseR1CS(1)
	expectedResult := fr_bn254.NewElement(6)

	publicVariables, secretVariables, variables, _ := backend.HandleValues(sparseR1CS, values, []uint32{})

	result, addedSecretVariables, variables := fromBinaryConversion([]int{0, 1, 2}, sparseR1CS, variables, true)
	assert.Equal(t, expectedResult, variables[result])

	secretVariables = append(secretVariables, addedSecretVariables...)
	assertThatProvingAndVerifyingSucceeds(t, publicVariables, secretVariables, sparseR1CS)
}
