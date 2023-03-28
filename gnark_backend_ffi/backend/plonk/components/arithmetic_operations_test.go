package plonk_components

import (
	"gnark_backend_ffi/backend"
	"testing"

	fr_bn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	cs_bn254 "github.com/consensys/gnark/constraint/bn254"
	"github.com/stretchr/testify/assert"
)

func TestAddComponent(t *testing.T) {
	values := fr_bn254.Vector{fr_bn254.NewElement(3), fr_bn254.NewElement(2)}
	sparseR1CS := cs_bn254.NewSparseR1CS(1)
	expectedResult := fr_bn254.NewElement(5)

	publicVariables, secretVariables, _ := backend.HandleValues(sparseR1CS, values, []uint32{})

	result, secretVariables := add(0, 1, sparseR1CS, secretVariables)
	assert.Equal(t, expectedResult, secretVariables[result])
	result, secretVariables = add(1, 0, sparseR1CS, secretVariables)
	assert.Equal(t, expectedResult, secretVariables[result])

	assertThatProvingAndVerifyingSucceeds(t, publicVariables, secretVariables, sparseR1CS)
}

func TestMulComponent(t *testing.T) {
	values := fr_bn254.Vector{fr_bn254.NewElement(2), fr_bn254.NewElement(3)}
	sparseR1CS := cs_bn254.NewSparseR1CS(1)
	expectedResult := fr_bn254.NewElement(6)

	publicVariables, secretVariables, _ := backend.HandleValues(sparseR1CS, values, []uint32{})

	result, secretVariables := mul(0, 1, sparseR1CS, secretVariables)
	assert.Equal(t, expectedResult, secretVariables[result])
	result, secretVariables = mul(1, 0, sparseR1CS, secretVariables)
	assert.Equal(t, expectedResult, secretVariables[result])

	assertThatProvingAndVerifyingSucceeds(t, publicVariables, secretVariables, sparseR1CS)
}
