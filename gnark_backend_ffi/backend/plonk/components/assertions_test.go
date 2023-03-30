package components

import (
	"gnark_backend_ffi/acir"
	"gnark_backend_ffi/backend"
	"testing"

	fr_bn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	cs_bn254 "github.com/consensys/gnark/constraint/bn254"
)

func TestAssertIsBooleanComponentWithBooleans(t *testing.T) {
	values := fr_bn254.Vector{fr_bn254.NewElement(0), fr_bn254.One()}
	sparseR1CS := cs_bn254.NewSparseR1CS(1)

	publicVariables, secretVariables, variables, variablesMap := backend.HandleValues(sparseR1CS, values, []uint32{})
	ctx := backend.NewContext(acir.ACIR{}, sparseR1CS, publicVariables, secretVariables, variables, variablesMap)

	assertIsBoolean(0, sparseR1CS)
	assertIsBoolean(1, sparseR1CS)

	assertThatProvingAndVerifyingSucceeds(t, ctx)
}

func TestAssertIsBooleanComponentWithNonBooleans(t *testing.T) {
	values := fr_bn254.Vector{fr_bn254.NewElement(2)}
	sparseR1CS := cs_bn254.NewSparseR1CS(1)

	publicVariables, secretVariables, variables, variablesMap := backend.HandleValues(sparseR1CS, values, []uint32{})
	ctx := backend.NewContext(acir.ACIR{}, sparseR1CS, publicVariables, secretVariables, variables, variablesMap)

	assertIsBoolean(0, sparseR1CS)

	assertThatProvingFails(t, ctx)
}

func TestAssertIsEqualComponentWithEqualElements(t *testing.T) {
	values := fr_bn254.Vector{fr_bn254.NewElement(0), fr_bn254.One()}
	sparseR1CS := cs_bn254.NewSparseR1CS(1)

	publicVariables, secretVariables, variables, variablesMap := backend.HandleValues(sparseR1CS, values, []uint32{})
	ctx := backend.NewContext(acir.ACIR{}, sparseR1CS, publicVariables, secretVariables, variables, variablesMap)

	// TODO: I think that there is a bug in Gnark here. If you want to see it for
	// yourself, just remove the second assertIsEqual. It seems that when having
	// one constraint that it's supposed to be satisfied when proving, an error
	// rises, and in the same case but with a constraint system that it is not
	// supposed to be satisfied the proving goes well (see that TestAssertIsEqualComponentWithNonEqualElements)
	// passes. This is the same for every other similar test.
	assertIsEqual(0, 0, sparseR1CS)
	assertIsEqual(1, 1, sparseR1CS)

	assertThatProvingAndVerifyingSucceeds(t, ctx)
}

func TestAssertIsEqualComponentWithNonEqualElements(t *testing.T) {
	values := fr_bn254.Vector{fr_bn254.NewElement(2), fr_bn254.NewElement(3)}
	sparseR1CS := cs_bn254.NewSparseR1CS(1)

	publicVariables, secretVariables, variables, variablesMap := backend.HandleValues(sparseR1CS, values, []uint32{})
	ctx := backend.NewContext(acir.ACIR{}, sparseR1CS, publicVariables, secretVariables, variables, variablesMap)

	assertIsEqual(0, 1, sparseR1CS)

	assertThatProvingFails(t, ctx)
}

func TestAssertIsInRangeComponentSucceeds(t *testing.T) {
	values := fr_bn254.Vector{fr_bn254.NewElement(3)}
	amountOfBits := 2
	sparseR1CS := cs_bn254.NewSparseR1CS(1)

	publicVariables, secretVariables, variables, variablesMap := backend.HandleValues(sparseR1CS, values, []uint32{})
	ctx := backend.NewContext(acir.ACIR{}, sparseR1CS, publicVariables, secretVariables, variables, variablesMap)

	assertIsInRange(0, amountOfBits, ctx)
	assertIsInRange(0, amountOfBits+1, ctx)
	assertIsInRange(0, amountOfBits+2, ctx)

	assertThatProvingAndVerifyingSucceeds(t, ctx)
}

func TestAssertIsInRangeComponentFails(t *testing.T) {
	values := fr_bn254.Vector{fr_bn254.NewElement(3)}
	amountOfBits := 1
	sparseR1CS := cs_bn254.NewSparseR1CS(1)

	publicVariables, secretVariables, variables, variablesMap := backend.HandleValues(sparseR1CS, values, []uint32{})
	ctx := backend.NewContext(acir.ACIR{}, sparseR1CS, publicVariables, secretVariables, variables, variablesMap)

	assertIsInRange(0, amountOfBits, ctx)

	assertThatProvingFails(t, ctx)
}
