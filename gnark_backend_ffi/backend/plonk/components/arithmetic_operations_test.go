package components

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
	var addedSecretVariables fr_bn254.Vector

	publicVariables, secretVariables, variables, _ := backend.HandleValues(sparseR1CS, values, []uint32{})

	result, _addedSecretVariables, variables := add(0, 1, sparseR1CS, variables)
	addedSecretVariables = append(addedSecretVariables, _addedSecretVariables...)
	assert.Equal(t, expectedResult, variables[result])
	result, _addedSecretVariables, variables = add(1, 0, sparseR1CS, variables)
	addedSecretVariables = append(addedSecretVariables, _addedSecretVariables...)
	assert.Equal(t, expectedResult, variables[result])

	secretVariables = append(secretVariables, addedSecretVariables...)
	assertThatProvingAndVerifyingSucceeds(t, publicVariables, secretVariables, sparseR1CS)
}

func TestMulComponent(t *testing.T) {
	values := fr_bn254.Vector{fr_bn254.NewElement(2), fr_bn254.NewElement(3)}
	sparseR1CS := cs_bn254.NewSparseR1CS(1)
	expectedResult := fr_bn254.NewElement(6)
	var addedSecretVariables fr_bn254.Vector

	publicVariables, secretVariables, variables, _ := backend.HandleValues(sparseR1CS, values, []uint32{})

	result, _addedSecretVariables, variables := mul(0, 1, sparseR1CS, variables)
	addedSecretVariables = append(addedSecretVariables, _addedSecretVariables...)
	assert.Equal(t, expectedResult, variables[result])
	result, _addedSecretVariables, variables = mul(1, 0, sparseR1CS, variables)
	addedSecretVariables = append(addedSecretVariables, _addedSecretVariables...)
	assert.Equal(t, expectedResult, variables[result])

	secretVariables = append(secretVariables, addedSecretVariables...)
	assertThatProvingAndVerifyingSucceeds(t, publicVariables, secretVariables, sparseR1CS)
}
