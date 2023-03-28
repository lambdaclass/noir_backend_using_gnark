package plonk_components

import (
	"fmt"
	"gnark_backend_ffi/backend"
	"testing"

	fr_bn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	cs_bn254 "github.com/consensys/gnark/constraint/bn254"
	"github.com/stretchr/testify/assert"
)

func TestBitAndComponentWithBooleans(t *testing.T) {
	values := fr_bn254.Vector{fr_bn254.NewElement(0), fr_bn254.One()}
	sparseR1CS := cs_bn254.NewSparseR1CS(1)
	one := fr_bn254.One()
	zero := fr_bn254.NewElement(0)
	var addedSecretVariables fr_bn254.Vector

	publicVariables, secretVariables, variables, _ := backend.HandleValues(sparseR1CS, values, []uint32{})

	result, _addedSecretVariables, variables := and(0, 0, sparseR1CS, variables, true)
	addedSecretVariables = append(addedSecretVariables, _addedSecretVariables...)
	assert.Equal(t, zero, variables[result])
	result, _addedSecretVariables, variables = and(0, 1, sparseR1CS, variables, true)
	addedSecretVariables = append(addedSecretVariables, _addedSecretVariables...)
	assert.Equal(t, zero, variables[result])
	result, _addedSecretVariables, variables = and(1, 0, sparseR1CS, variables, true)
	addedSecretVariables = append(addedSecretVariables, _addedSecretVariables...)
	assert.Equal(t, zero, variables[result])
	result, _addedSecretVariables, variables = and(1, 1, sparseR1CS, variables, true)
	addedSecretVariables = append(addedSecretVariables, _addedSecretVariables...)
	assert.Equal(t, one, variables[result])

	secretVariables = append(secretVariables, addedSecretVariables...)
	assertThatProvingAndVerifyingSucceeds(t, publicVariables, secretVariables, sparseR1CS)
}

func TestBitAndComponentWithNonBooleans(t *testing.T) {
	values := fr_bn254.Vector{fr_bn254.NewElement(2), fr_bn254.NewElement(3)}
	sparseR1CS := cs_bn254.NewSparseR1CS(1)
	one := fr_bn254.One()
	zero := fr_bn254.NewElement(0)
	var addedSecretVariables fr_bn254.Vector

	publicVariables, secretVariables, variables, _ := backend.HandleValues(sparseR1CS, values, []uint32{})

	result, _addedSecretVariables, variables := and(0, 0, sparseR1CS, variables, true)
	addedSecretVariables = append(addedSecretVariables, _addedSecretVariables...)
	assert.NotEqual(t, zero, variables[result])
	assert.NotEqual(t, one, variables[result])
	result, _addedSecretVariables, variables = and(0, 1, sparseR1CS, variables, true)
	addedSecretVariables = append(addedSecretVariables, _addedSecretVariables...)
	assert.NotEqual(t, zero, variables[result])
	assert.NotEqual(t, one, variables[result])
	result, _addedSecretVariables, variables = and(1, 0, sparseR1CS, variables, true)
	addedSecretVariables = append(addedSecretVariables, _addedSecretVariables...)
	assert.NotEqual(t, zero, variables[result])
	assert.NotEqual(t, one, variables[result])
	result, _addedSecretVariables, variables = and(1, 1, sparseR1CS, variables, true)
	addedSecretVariables = append(addedSecretVariables, _addedSecretVariables...)
	assert.NotEqual(t, zero, variables[result])
	assert.NotEqual(t, one, variables[result])

	secretVariables = append(secretVariables, addedSecretVariables...)
	assertThatProvingFails(t, publicVariables, secretVariables, sparseR1CS)
}

func TestFeltAndComponent(t *testing.T) {
	zero := fr_bn254.NewElement(0)
	one := fr_bn254.One()
	two := fr_bn254.NewElement(2)
	six := fr_bn254.NewElement(6)
	values := fr_bn254.Vector{zero, one, two, six}
	sparseR1CS := cs_bn254.NewSparseR1CS(1)
	var addedSecretVariables fr_bn254.Vector

	publicVariables, secretVariables, variables, _ := backend.HandleValues(sparseR1CS, values, []uint32{})

	// 0 & 0
	result, _addedSecretVariables, variables := And(0, 0, 1, sparseR1CS, variables)
	addedSecretVariables = append(addedSecretVariables, _addedSecretVariables...)
	assert.Equal(t, zero, variables[result])
	// 0 & 1
	result, _addedSecretVariables, variables = And(0, 1, 1, sparseR1CS, variables)
	addedSecretVariables = append(addedSecretVariables, _addedSecretVariables...)
	assert.Equal(t, zero, variables[result])
	// 1 & 1
	result, _addedSecretVariables, variables = And(1, 1, 1, sparseR1CS, variables)
	addedSecretVariables = append(addedSecretVariables, _addedSecretVariables...)
	assert.Equal(t, one, variables[result])
	// 1 & 2
	result, _addedSecretVariables, variables = And(1, 2, 2, sparseR1CS, variables)
	addedSecretVariables = append(addedSecretVariables, _addedSecretVariables...)
	assert.Equal(t, zero, variables[result])
	// 2 & 2
	result, _addedSecretVariables, variables = And(2, 2, 2, sparseR1CS, variables)
	addedSecretVariables = append(addedSecretVariables, _addedSecretVariables...)
	assert.Equal(t, two, variables[result])
	// 6 & 6
	result, _addedSecretVariables, variables = And(3, 3, 3, sparseR1CS, variables)
	addedSecretVariables = append(addedSecretVariables, _addedSecretVariables...)
	assert.Equal(t, six, variables[result])

	secretVariables = append(secretVariables, addedSecretVariables...)
	assertThatProvingAndVerifyingSucceeds(t, publicVariables, secretVariables, sparseR1CS)
}

func TestBitXorComponentWithBooleans(t *testing.T) {
	values := fr_bn254.Vector{fr_bn254.NewElement(0), fr_bn254.One()}
	sparseR1CS := cs_bn254.NewSparseR1CS(1)
	one := fr_bn254.One()
	zero := fr_bn254.NewElement(0)
	var addedSecretVariables fr_bn254.Vector

	publicVariables, secretVariables, variables, _ := backend.HandleValues(sparseR1CS, values, []uint32{})

	result, _addedSecretVariables, variables := xor(0, 0, sparseR1CS, variables, true)
	addedSecretVariables = append(addedSecretVariables, _addedSecretVariables...)
	assert.Equal(t, zero, variables[result])
	result, _addedSecretVariables, variables = xor(0, 1, sparseR1CS, variables, true)
	addedSecretVariables = append(addedSecretVariables, _addedSecretVariables...)
	assert.Equal(t, one, variables[result])
	result, _addedSecretVariables, variables = xor(1, 0, sparseR1CS, variables, true)
	addedSecretVariables = append(addedSecretVariables, _addedSecretVariables...)
	assert.Equal(t, one, variables[result])
	result, _addedSecretVariables, variables = xor(1, 1, sparseR1CS, variables, true)
	addedSecretVariables = append(addedSecretVariables, _addedSecretVariables...)
	assert.Equal(t, zero, variables[result])

	secretVariables = append(secretVariables, addedSecretVariables...)
	assertThatProvingAndVerifyingSucceeds(t, publicVariables, secretVariables, sparseR1CS)
}

func TestBitXorComponentWithNonBooleans(t *testing.T) {
	values := fr_bn254.Vector{fr_bn254.NewElement(2), fr_bn254.NewElement(3)}
	sparseR1CS := cs_bn254.NewSparseR1CS(1)
	one := fr_bn254.One()
	zero := fr_bn254.NewElement(0)
	var addedSecretVariables fr_bn254.Vector

	publicVariables, secretVariables, variables, _ := backend.HandleValues(sparseR1CS, values, []uint32{})

	result, _addedSecretVariables, variables := xor(0, 0, sparseR1CS, variables, true)
	addedSecretVariables = append(addedSecretVariables, _addedSecretVariables...)
	assert.NotEqual(t, zero, variables[result])
	assert.NotEqual(t, one, variables[result])
	result, _addedSecretVariables, variables = xor(0, 1, sparseR1CS, variables, true)
	addedSecretVariables = append(addedSecretVariables, _addedSecretVariables...)
	assert.NotEqual(t, zero, variables[result])
	assert.NotEqual(t, one, variables[result])
	result, _addedSecretVariables, variables = xor(1, 0, sparseR1CS, variables, true)
	addedSecretVariables = append(addedSecretVariables, _addedSecretVariables...)
	assert.NotEqual(t, zero, variables[result])
	assert.NotEqual(t, one, variables[result])
	result, _addedSecretVariables, variables = xor(1, 1, sparseR1CS, variables, true)
	addedSecretVariables = append(addedSecretVariables, _addedSecretVariables...)
	assert.NotEqual(t, zero, variables[result])
	assert.NotEqual(t, one, variables[result])

	secretVariables = append(secretVariables, addedSecretVariables...)
	assertThatProvingFails(t, publicVariables, secretVariables, sparseR1CS)
}

func TestFeltXorComponent(t *testing.T) {
	zero := fr_bn254.NewElement(0)
	one := fr_bn254.One()
	two := fr_bn254.NewElement(2)
	three := fr_bn254.NewElement(3)
	six := fr_bn254.NewElement(6)
	seven := fr_bn254.NewElement(7)
	values := fr_bn254.Vector{zero, one, two, six}
	sparseR1CS := cs_bn254.NewSparseR1CS(1)
	var addedSecretVariables fr_bn254.Vector

	publicVariables, secretVariables, variables, _ := backend.HandleValues(sparseR1CS, values, []uint32{})

	// 0 ^ 0 = 0
	result, _addedSecretVariables, variables := Xor(0, 0, 1, sparseR1CS, variables)
	addedSecretVariables = append(addedSecretVariables, _addedSecretVariables...)
	fmt.Println("ADDED", addedSecretVariables)
	fmt.Println(variables)
	assert.Equal(t, zero, variables[result])
	// 0 ^ 1 = 1
	result, _addedSecretVariables, variables = Xor(0, 1, 1, sparseR1CS, variables)
	addedSecretVariables = append(addedSecretVariables, _addedSecretVariables...)
	fmt.Println("ADDED", addedSecretVariables)
	fmt.Println(variables)
	assert.Equal(t, one, variables[result])
	// 1 ^ 1 = 0
	result, _addedSecretVariables, variables = Xor(1, 1, 1, sparseR1CS, variables)
	addedSecretVariables = append(addedSecretVariables, _addedSecretVariables...)
	assert.Equal(t, zero, variables[result])
	// 1 ^ 2 = 3
	result, _addedSecretVariables, variables = Xor(1, 2, 2, sparseR1CS, variables)
	addedSecretVariables = append(addedSecretVariables, _addedSecretVariables...)
	assert.Equal(t, three, variables[result])
	// 2 ^ 2 = 0
	result, _addedSecretVariables, variables = Xor(2, 2, 2, sparseR1CS, variables)
	addedSecretVariables = append(addedSecretVariables, _addedSecretVariables...)
	assert.Equal(t, zero, variables[result])
	// 1 ^ 6 = 7
	result, _addedSecretVariables, variables = Xor(1, 3, 3, sparseR1CS, variables)
	addedSecretVariables = append(addedSecretVariables, _addedSecretVariables...)
	assert.Equal(t, seven, variables[result])

	secretVariables = append(secretVariables, addedSecretVariables...)
	assertThatProvingAndVerifyingSucceeds(t, publicVariables, secretVariables, sparseR1CS)
}
