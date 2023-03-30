package components

import (
	"gnark_backend_ffi/acir"
	"gnark_backend_ffi/backend"
	"testing"

	fr_bn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	cs_bn254 "github.com/consensys/gnark/constraint/bn254"
	"github.com/stretchr/testify/assert"
)

func TestToBinaryConversionWithNoBits(t *testing.T) {
	values := fr_bn254.Vector{fr_bn254.One()}
	sparseR1CS := cs_bn254.NewSparseR1CS(1)

	publicVariables, secretVariables, variables, variablesMap := backend.HandleValues(sparseR1CS, values, []uint32{})
	ctx := backend.NewContext(acir.ACIR{}, sparseR1CS, publicVariables, secretVariables, variables, variablesMap)

	result := toBinaryConversion(0, 0, ctx)
	assert.Empty(t, result)

	assertThatProvingFails(t, ctx)
}

func TestToBinaryConversionWithOneBit(t *testing.T) {
	values := fr_bn254.Vector{fr_bn254.One()}
	sparseR1CS := cs_bn254.NewSparseR1CS(1)

	publicVariables, secretVariables, variables, variablesMap := backend.HandleValues(sparseR1CS, values, []uint32{})
	ctx := backend.NewContext(acir.ACIR{}, sparseR1CS, publicVariables, secretVariables, variables, variablesMap)

	result := toBinaryConversion(0, 1, ctx)
	assert.Equal(t, fr_bn254.One(), ctx.Variables[result[0]])

	assertThatProvingAndVerifyingSucceeds(t, ctx)
}

func TestToBinaryConversionWithMoreThanOneBit(t *testing.T) {
	values := fr_bn254.Vector{fr_bn254.NewElement(3)}
	sparseR1CS := cs_bn254.NewSparseR1CS(1)

	publicVariables, secretVariables, variables, variablesMap := backend.HandleValues(sparseR1CS, values, []uint32{})
	ctx := backend.NewContext(acir.ACIR{}, sparseR1CS, publicVariables, secretVariables, variables, variablesMap)

	result := toBinaryConversion(0, 2, ctx)
	assert.Equal(t, fr_bn254.One(), ctx.Variables[result[0]])
	assert.Equal(t, fr_bn254.One(), ctx.Variables[result[1]])

	assertThatProvingAndVerifyingSucceeds(t, ctx)
}

func TestFromBinaryConversionWithOneBit(t *testing.T) {
	one := fr_bn254.One()
	values := fr_bn254.Vector{one}
	sparseR1CS := cs_bn254.NewSparseR1CS(1)

	publicVariables, secretVariables, variables, variablesMap := backend.HandleValues(sparseR1CS, values, []uint32{})
	ctx := backend.NewContext(acir.ACIR{}, sparseR1CS, publicVariables, secretVariables, variables, variablesMap)

	binaryResult := toBinaryConversion(0, 1, ctx)
	result := fromBinaryConversion(binaryResult, ctx, false)
	assert.Equal(t, one, ctx.Variables[result])

	assertThatProvingAndVerifyingSucceeds(t, ctx)
}

func TestFromBinaryConversionWithMoreThanOneBit(t *testing.T) {
	three := fr_bn254.NewElement(3)
	values := fr_bn254.Vector{three}
	sparseR1CS := cs_bn254.NewSparseR1CS(1)

	publicVariables, secretVariables, variables, variablesMap := backend.HandleValues(sparseR1CS, values, []uint32{})
	ctx := backend.NewContext(acir.ACIR{}, sparseR1CS, publicVariables, secretVariables, variables, variablesMap)

	binaryResult := toBinaryConversion(0, 2, ctx)
	result := fromBinaryConversion(binaryResult, ctx, false)
	assert.Equal(t, three, ctx.Variables[result])

	assertThatProvingAndVerifyingSucceeds(t, ctx)
}

func TestFromBinaryConversionWithUnconstrainedInputs(t *testing.T) {
	one := fr_bn254.One()
	zero := fr_bn254.NewElement(0)
	values := fr_bn254.Vector{one, one, zero}
	sparseR1CS := cs_bn254.NewSparseR1CS(1)
	expectedResult := fr_bn254.NewElement(6)

	publicVariables, secretVariables, variables, variablesMap := backend.HandleValues(sparseR1CS, values, []uint32{})
	ctx := backend.NewContext(acir.ACIR{}, sparseR1CS, publicVariables, secretVariables, variables, variablesMap)

	result := fromBinaryConversion([]int{0, 1, 2}, ctx, true)
	assert.Equal(t, expectedResult, ctx.Variables[result])

	assertThatProvingAndVerifyingSucceeds(t, ctx)
}
