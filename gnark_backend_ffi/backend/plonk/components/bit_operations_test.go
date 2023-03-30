package components

import (
	"gnark_backend_ffi/acir"
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

	publicVariables, secretVariables, variables, variablesMap := backend.HandleValues(sparseR1CS, values, []uint32{})
	ctx := backend.NewContext(acir.ACIR{}, sparseR1CS, publicVariables, secretVariables, variables, variablesMap)

	result := and(0, 0, ctx, true)
	assert.Equal(t, zero, ctx.Variables[result])
	result = and(0, 1, ctx, true)
	assert.Equal(t, zero, ctx.Variables[result])
	result = and(1, 0, ctx, true)
	assert.Equal(t, zero, ctx.Variables[result])
	result = and(1, 1, ctx, true)
	assert.Equal(t, one, ctx.Variables[result])

	assertThatProvingAndVerifyingSucceeds(t, ctx)
}

func TestBitAndComponentWithNonBooleans(t *testing.T) {
	values := fr_bn254.Vector{fr_bn254.NewElement(2), fr_bn254.NewElement(3)}
	sparseR1CS := cs_bn254.NewSparseR1CS(1)
	one := fr_bn254.One()
	zero := fr_bn254.NewElement(0)

	publicVariables, secretVariables, variables, variablesMap := backend.HandleValues(sparseR1CS, values, []uint32{})
	ctx := backend.NewContext(acir.ACIR{}, sparseR1CS, publicVariables, secretVariables, variables, variablesMap)

	result := and(0, 0, ctx, true)
	assert.NotEqual(t, zero, ctx.Variables[result])
	assert.NotEqual(t, one, ctx.Variables[result])
	result = and(0, 1, ctx, true)
	assert.NotEqual(t, zero, ctx.Variables[result])
	assert.NotEqual(t, one, ctx.Variables[result])
	result = and(1, 0, ctx, true)
	assert.NotEqual(t, zero, ctx.Variables[result])
	assert.NotEqual(t, one, ctx.Variables[result])
	result = and(1, 1, ctx, true)
	assert.NotEqual(t, zero, ctx.Variables[result])
	assert.NotEqual(t, one, ctx.Variables[result])

	assertThatProvingFails(t, ctx)
}

func TestFeltAndComponent(t *testing.T) {
	zero := fr_bn254.NewElement(0)
	one := fr_bn254.One()
	two := fr_bn254.NewElement(2)
	six := fr_bn254.NewElement(6)
	values := fr_bn254.Vector{zero, one, two, six}
	sparseR1CS := cs_bn254.NewSparseR1CS(1)

	publicVariables, secretVariables, variables, variablesMap := backend.HandleValues(sparseR1CS, values, []uint32{})
	ctx := backend.NewContext(acir.ACIR{}, sparseR1CS, publicVariables, secretVariables, variables, variablesMap)

	// 0 & 0
	result := And(0, 0, 1, ctx)
	assert.Equal(t, zero, ctx.Variables[result])
	// 0 & 1
	result = And(0, 1, 1, ctx)
	assert.Equal(t, zero, ctx.Variables[result])
	// 1 & 1
	result = And(1, 1, 1, ctx)
	assert.Equal(t, one, ctx.Variables[result])
	// 1 & 2
	result = And(1, 2, 2, ctx)
	assert.Equal(t, zero, ctx.Variables[result])
	// 2 & 2
	result = And(2, 2, 2, ctx)
	assert.Equal(t, two, ctx.Variables[result])
	// 6 & 6
	result = And(3, 3, 3, ctx)
	assert.Equal(t, six, ctx.Variables[result])

	assertThatProvingAndVerifyingSucceeds(t, ctx)
}

func TestBitXorComponentWithBooleans(t *testing.T) {
	values := fr_bn254.Vector{fr_bn254.NewElement(0), fr_bn254.One()}
	sparseR1CS := cs_bn254.NewSparseR1CS(1)
	one := fr_bn254.One()
	zero := fr_bn254.NewElement(0)

	publicVariables, secretVariables, variables, variablesMap := backend.HandleValues(sparseR1CS, values, []uint32{})
	ctx := backend.NewContext(acir.ACIR{}, sparseR1CS, publicVariables, secretVariables, variables, variablesMap)

	result := xor(0, 0, ctx, true)
	assert.Equal(t, zero, ctx.Variables[result])
	result = xor(0, 1, ctx, true)
	assert.Equal(t, one, ctx.Variables[result])
	result = xor(1, 0, ctx, true)
	assert.Equal(t, one, ctx.Variables[result])
	result = xor(1, 1, ctx, true)
	assert.Equal(t, zero, ctx.Variables[result])

	assertThatProvingAndVerifyingSucceeds(t, ctx)
}

func TestBitXorComponentWithNonBooleans(t *testing.T) {
	values := fr_bn254.Vector{fr_bn254.NewElement(2), fr_bn254.NewElement(3)}
	sparseR1CS := cs_bn254.NewSparseR1CS(1)
	one := fr_bn254.One()
	zero := fr_bn254.NewElement(0)

	publicVariables, secretVariables, variables, variablesMap := backend.HandleValues(sparseR1CS, values, []uint32{})
	ctx := backend.NewContext(acir.ACIR{}, sparseR1CS, publicVariables, secretVariables, variables, variablesMap)

	result := xor(0, 0, ctx, true)
	assert.NotEqual(t, zero, ctx.Variables[result])
	assert.NotEqual(t, one, ctx.Variables[result])
	result = xor(0, 1, ctx, true)
	assert.NotEqual(t, zero, ctx.Variables[result])
	assert.NotEqual(t, one, ctx.Variables[result])
	result = xor(1, 0, ctx, true)
	assert.NotEqual(t, zero, ctx.Variables[result])
	assert.NotEqual(t, one, ctx.Variables[result])
	result = xor(1, 1, ctx, true)
	assert.NotEqual(t, zero, ctx.Variables[result])
	assert.NotEqual(t, one, ctx.Variables[result])

	assertThatProvingFails(t, ctx)
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

	publicVariables, secretVariables, variables, variablesMap := backend.HandleValues(sparseR1CS, values, []uint32{})
	ctx := backend.NewContext(acir.ACIR{}, sparseR1CS, publicVariables, secretVariables, variables, variablesMap)

	// 0 ^ 0 = 0
	result := Xor(0, 0, 1, ctx)
	assert.Equal(t, zero, ctx.Variables[result])
	// 0 ^ 1 = 1
	result = Xor(0, 1, 1, ctx)
	assert.Equal(t, one, ctx.Variables[result])
	// 1 ^ 1 = 0
	result = Xor(1, 1, 1, ctx)
	assert.Equal(t, zero, ctx.Variables[result])
	// 1 ^ 2 = 3
	result = Xor(1, 2, 2, ctx)
	assert.Equal(t, three, ctx.Variables[result])
	// 2 ^ 2 = 0
	result = Xor(2, 2, 2, ctx)
	assert.Equal(t, zero, ctx.Variables[result])
	// 1 ^ 6 = 7
	result = Xor(1, 3, 3, ctx)
	assert.Equal(t, seven, ctx.Variables[result])

	assertThatProvingAndVerifyingSucceeds(t, ctx)
}
