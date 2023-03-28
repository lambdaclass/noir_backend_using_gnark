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

	publicVariables, secretVariables, _ := backend.HandleValues(sparseR1CS, values, []uint32{})

	result, secretVariables := toBinaryConversion(0, 0, sparseR1CS, secretVariables)
	assert.Empty(t, result)

	assertThatProvingFails(t, publicVariables, secretVariables, sparseR1CS)
}

func TestToBinaryConversionWithOneBit(t *testing.T) {
	values := fr_bn254.Vector{fr_bn254.One()}
	sparseR1CS := cs_bn254.NewSparseR1CS(1)

	publicVariables, secretVariables, _ := backend.HandleValues(sparseR1CS, values, []uint32{})

	result, secretVariables := toBinaryConversion(0, 1, sparseR1CS, secretVariables)
	assert.Equal(t, fr_bn254.One(), secretVariables[result[0]])

	assertThatProvingAndVerifyingSucceeds(t, publicVariables, secretVariables, sparseR1CS)
}

func TestToBinaryConversionWithMoreThanOneBit(t *testing.T) {
	values := fr_bn254.Vector{fr_bn254.NewElement(3)}
	sparseR1CS := cs_bn254.NewSparseR1CS(1)

	publicVariables, secretVariables, _ := backend.HandleValues(sparseR1CS, values, []uint32{})

	result, secretVariables := toBinaryConversion(0, 2, sparseR1CS, secretVariables)
	assert.Equal(t, fr_bn254.One(), secretVariables[result[0]])
	assert.Equal(t, fr_bn254.One(), secretVariables[result[1]])

	assertThatProvingAndVerifyingSucceeds(t, publicVariables, secretVariables, sparseR1CS)
}

func TestFromBinaryConversionWithOneBit(t *testing.T) {
	one := fr_bn254.One()
	values := fr_bn254.Vector{one}
	sparseR1CS := cs_bn254.NewSparseR1CS(1)

	publicVariables, secretVariables, _ := backend.HandleValues(sparseR1CS, values, []uint32{})

	binaryResult, secretVariables := toBinaryConversion(0, 1, sparseR1CS, secretVariables)
	result, secretVariables := fromBinaryConversion(binaryResult, sparseR1CS, secretVariables, false)
	assert.Equal(t, one, secretVariables[result])

	assertThatProvingAndVerifyingSucceeds(t, publicVariables, secretVariables, sparseR1CS)
}

func TestFromBinaryConversionWithMoreThanOneBit(t *testing.T) {
	three := fr_bn254.NewElement(3)
	values := fr_bn254.Vector{three}
	sparseR1CS := cs_bn254.NewSparseR1CS(1)

	publicVariables, secretVariables, _ := backend.HandleValues(sparseR1CS, values, []uint32{})

	binaryResult, secretVariables := toBinaryConversion(0, 2, sparseR1CS, secretVariables)
	result, secretVariables := fromBinaryConversion(binaryResult, sparseR1CS, secretVariables, false)
	assert.Equal(t, three, secretVariables[result])

	assertThatProvingAndVerifyingSucceeds(t, publicVariables, secretVariables, sparseR1CS)
}

func TestFromBinaryConversionWithUnconstrainedInputs(t *testing.T) {
	one := fr_bn254.One()
	zero := fr_bn254.NewElement(0)
	values := fr_bn254.Vector{one, one, zero}
	sparseR1CS := cs_bn254.NewSparseR1CS(1)
	expectedResult := fr_bn254.NewElement(6)

	publicVariables, secretVariables, _ := backend.HandleValues(sparseR1CS, values, []uint32{})

	result, secretVariables := fromBinaryConversion([]int{0, 1, 2}, sparseR1CS, secretVariables, true)
	assert.Equal(t, expectedResult, secretVariables[result])

	assertThatProvingAndVerifyingSucceeds(t, publicVariables, secretVariables, sparseR1CS)
}
