package components

import (
	"gnark_backend_ffi/acir"
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

	publicVariables, secretVariables, variables, variablesMap := backend.HandleValues(sparseR1CS, values, []uint32{})
	ctx := backend.NewContext(acir.ACIR{}, sparseR1CS, publicVariables, secretVariables, variables, variablesMap)

	result := add(0, 1, ctx)
	assert.Equal(t, expectedResult, ctx.Variables[result])
	result = add(1, 0, ctx)
	assert.Equal(t, expectedResult, ctx.Variables[result])

	assertThatProvingAndVerifyingSucceeds(t, ctx)
}

func TestMulComponent(t *testing.T) {
	values := fr_bn254.Vector{fr_bn254.NewElement(2), fr_bn254.NewElement(3)}
	sparseR1CS := cs_bn254.NewSparseR1CS(1)
	expectedResult := fr_bn254.NewElement(6)

	publicVariables, secretVariables, variables, variablesMap := backend.HandleValues(sparseR1CS, values, []uint32{})
	ctx := backend.NewContext(acir.ACIR{}, sparseR1CS, publicVariables, secretVariables, variables, variablesMap)

	result := mul(0, 1, ctx)
	assert.Equal(t, expectedResult, ctx.Variables[result])
	result = mul(1, 0, ctx)
	assert.Equal(t, expectedResult, ctx.Variables[result])

	assertThatProvingAndVerifyingSucceeds(t, ctx)
}

func TestSubComponent(t *testing.T) {
	values := fr_bn254.Vector{fr_bn254.NewElement(3), fr_bn254.NewElement(2)}
	sparseR1CS := cs_bn254.NewSparseR1CS(1)
	negativeOne := fr_bn254.Element{10902020042510041094, 17381486299841078119, 5900175412809962030, 2475245527108272378}

	publicVariables, secretVariables, variables, variablesMap := backend.HandleValues(sparseR1CS, values, []uint32{})
	ctx := backend.NewContext(acir.ACIR{}, sparseR1CS, publicVariables, secretVariables, variables, variablesMap)

	// 3 - 2 = 1
	result := sub(0, 1, ctx)
	assert.Equal(t, fr_bn254.One(), ctx.Variables[result])
	// 2 - 2 = 0
	result = sub(0, 0, ctx)
	assert.Equal(t, fr_bn254.NewElement(0), ctx.Variables[result])
	// 2 - 3 = -1
	result = sub(1, 0, ctx)
	assert.Equal(t, negativeOne, ctx.Variables[result])

	assertThatProvingAndVerifyingSucceeds(t, ctx)
}
