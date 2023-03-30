package components

import (
	"gnark_backend_ffi/acir"
	"gnark_backend_ffi/backend"
	"testing"

	fr_bn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	cs_bn254 "github.com/consensys/gnark/constraint/bn254"
	"github.com/stretchr/testify/assert"
)

func TestSelectComponent(t *testing.T) {
	three := fr_bn254.NewElement(3)
	four := fr_bn254.NewElement(4)
	values := fr_bn254.Vector{fr_bn254.NewElement(0), fr_bn254.One(), three, four}
	sparseR1CS := cs_bn254.NewSparseR1CS(1)

	publicVariables, secretVariables, variables, variablesMap := backend.HandleValues(sparseR1CS, values, []uint32{})
	ctx := backend.NewContext(acir.ACIR{}, sparseR1CS, publicVariables, secretVariables, variables, variablesMap)

	trueResult := Select(1, 2, 3, ctx, true)
	assert.Equal(t, three, ctx.Variables[trueResult])
	falseResult := Select(0, 2, 3, ctx, true)
	assert.Equal(t, four, ctx.Variables[falseResult])

	assertThatProvingAndVerifyingSucceeds(t, ctx)
}
