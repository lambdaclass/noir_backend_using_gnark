package plonk_components

import (
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

	publicVariables, secretVariables, _ := backend.HandleValues(sparseR1CS, values, []uint32{})

	result, secretVariables := and(0, 0, sparseR1CS, secretVariables, true)
	assert.Equal(t, zero, secretVariables[result])
	result, secretVariables = and(0, 1, sparseR1CS, secretVariables, true)
	assert.Equal(t, zero, secretVariables[result])
	result, secretVariables = and(1, 0, sparseR1CS, secretVariables, true)
	assert.Equal(t, zero, secretVariables[result])
	result, secretVariables = and(1, 1, sparseR1CS, secretVariables, true)
	assert.Equal(t, one, secretVariables[result])

	assertThatProvingAndVerifyingSucceeds(t, publicVariables, secretVariables, sparseR1CS)
}

func TestBitAndComponentWithNonBooleans(t *testing.T) {
	values := fr_bn254.Vector{fr_bn254.NewElement(2), fr_bn254.NewElement(3)}
	sparseR1CS := cs_bn254.NewSparseR1CS(1)
	one := fr_bn254.One()
	zero := fr_bn254.NewElement(0)

	publicVariables, secretVariables, _ := backend.HandleValues(sparseR1CS, values, []uint32{})

	result, secretVariables := and(0, 0, sparseR1CS, secretVariables, true)
	assert.NotEqual(t, zero, secretVariables[result])
	assert.NotEqual(t, one, secretVariables[result])
	result, secretVariables = and(0, 1, sparseR1CS, secretVariables, true)
	assert.NotEqual(t, zero, secretVariables[result])
	assert.NotEqual(t, one, secretVariables[result])
	result, secretVariables = and(1, 0, sparseR1CS, secretVariables, true)
	assert.NotEqual(t, zero, secretVariables[result])
	assert.NotEqual(t, one, secretVariables[result])
	result, secretVariables = and(1, 1, sparseR1CS, secretVariables, true)
	assert.NotEqual(t, zero, secretVariables[result])
	assert.NotEqual(t, one, secretVariables[result])

	assertThatProvingFails(t, publicVariables, secretVariables, sparseR1CS)
}

func TestFeltAndComponent(t *testing.T) {
	zero := fr_bn254.NewElement(0)
	one := fr_bn254.One()
	two := fr_bn254.NewElement(2)
	six := fr_bn254.NewElement(6)
	values := fr_bn254.Vector{zero, one, two, six}
	sparseR1CS := cs_bn254.NewSparseR1CS(1)

	publicVariables, secretVariables, _ := backend.HandleValues(sparseR1CS, values, []uint32{})

	// 0 & 0
	result, secretVariables := And(0, 0, 1, sparseR1CS, secretVariables)
	assert.Equal(t, zero, secretVariables[result])
	// 0 & 1
	result, secretVariables = And(0, 1, 1, sparseR1CS, secretVariables)
	assert.Equal(t, zero, secretVariables[result])
	// 1 & 1
	result, secretVariables = And(1, 1, 1, sparseR1CS, secretVariables)
	assert.Equal(t, one, secretVariables[result])
	// 1 & 2
	result, secretVariables = And(1, 2, 2, sparseR1CS, secretVariables)
	assert.Equal(t, zero, secretVariables[result])
	// 2 & 2
	result, secretVariables = And(2, 2, 2, sparseR1CS, secretVariables)
	assert.Equal(t, two, secretVariables[result])
	// 6 & 6
	result, secretVariables = And(3, 3, 3, sparseR1CS, secretVariables)
	assert.Equal(t, six, secretVariables[result])

	assertThatProvingAndVerifyingSucceeds(t, publicVariables, secretVariables, sparseR1CS)
}

func TestBitXorComponentWithBooleans(t *testing.T) {
	values := fr_bn254.Vector{fr_bn254.NewElement(0), fr_bn254.One()}
	sparseR1CS := cs_bn254.NewSparseR1CS(1)
	one := fr_bn254.One()
	zero := fr_bn254.NewElement(0)

	publicVariables, secretVariables, _ := backend.HandleValues(sparseR1CS, values, []uint32{})

	result, secretVariables := xor(0, 0, sparseR1CS, secretVariables, true)
	assert.Equal(t, zero, secretVariables[result])
	result, secretVariables = xor(0, 1, sparseR1CS, secretVariables, true)
	assert.Equal(t, one, secretVariables[result])
	result, secretVariables = xor(1, 0, sparseR1CS, secretVariables, true)
	assert.Equal(t, one, secretVariables[result])
	result, secretVariables = xor(1, 1, sparseR1CS, secretVariables, true)
	assert.Equal(t, zero, secretVariables[result])

	assertThatProvingAndVerifyingSucceeds(t, publicVariables, secretVariables, sparseR1CS)
}

func TestBitXorComponentWithNonBooleans(t *testing.T) {
	values := fr_bn254.Vector{fr_bn254.NewElement(2), fr_bn254.NewElement(3)}
	sparseR1CS := cs_bn254.NewSparseR1CS(1)
	one := fr_bn254.One()
	zero := fr_bn254.NewElement(0)

	publicVariables, secretVariables, _ := backend.HandleValues(sparseR1CS, values, []uint32{})

	result, secretVariables := xor(0, 0, sparseR1CS, secretVariables, true)
	assert.NotEqual(t, zero, secretVariables[result])
	assert.NotEqual(t, one, secretVariables[result])
	result, secretVariables = xor(0, 1, sparseR1CS, secretVariables, true)
	assert.NotEqual(t, zero, secretVariables[result])
	assert.NotEqual(t, one, secretVariables[result])
	result, secretVariables = xor(1, 0, sparseR1CS, secretVariables, true)
	assert.NotEqual(t, zero, secretVariables[result])
	assert.NotEqual(t, one, secretVariables[result])
	result, secretVariables = xor(1, 1, sparseR1CS, secretVariables, true)
	assert.NotEqual(t, zero, secretVariables[result])
	assert.NotEqual(t, one, secretVariables[result])

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

	publicVariables, secretVariables, _ := backend.HandleValues(sparseR1CS, values, []uint32{})

	// 0 ^ 0 = 0
	result, secretVariables := Xor(0, 0, 1, sparseR1CS, secretVariables)
	assert.Equal(t, zero, secretVariables[result])
	// 0 ^ 1 = 1
	result, secretVariables = Xor(0, 1, 1, sparseR1CS, secretVariables)
	assert.Equal(t, one, secretVariables[result])
	// 1 ^ 1 = 0
	result, secretVariables = Xor(1, 1, 1, sparseR1CS, secretVariables)
	assert.Equal(t, zero, secretVariables[result])
	// 1 ^ 2 = 3
	result, secretVariables = Xor(1, 2, 2, sparseR1CS, secretVariables)
	assert.Equal(t, three, secretVariables[result])
	// 2 ^ 2 = 0
	result, secretVariables = Xor(2, 2, 2, sparseR1CS, secretVariables)
	assert.Equal(t, zero, secretVariables[result])
	// 1 ^ 6 = 7
	result, secretVariables = Xor(1, 3, 3, sparseR1CS, secretVariables)
	assert.Equal(t, seven, secretVariables[result])

	assertThatProvingAndVerifyingSucceeds(t, publicVariables, secretVariables, sparseR1CS)
}
