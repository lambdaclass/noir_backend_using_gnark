package plonk_components

import (
	"fmt"
	"gnark_backend_ffi/backend"
	"testing"

	fr_bn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	cs_bn254 "github.com/consensys/gnark/constraint/bn254"
)

func TestAssertIsBooleanComponentWithBooleans(t *testing.T) {
	values := fr_bn254.Vector{fr_bn254.NewElement(0), fr_bn254.One()}
	sparseR1CS := cs_bn254.NewSparseR1CS(1)

	publicVariables, secretVariables, _ := backend.HandleValues(sparseR1CS, values, []uint32{})

	assertIsBoolean(0, sparseR1CS)
	assertIsBoolean(1, sparseR1CS)

	assertThatProvingAndVerifyingSucceeds(t, publicVariables, secretVariables, sparseR1CS)
}

func TestAssertIsBooleanComponentWithNonBooleans(t *testing.T) {
	values := fr_bn254.Vector{fr_bn254.NewElement(2)}
	sparseR1CS := cs_bn254.NewSparseR1CS(1)

	publicVariables, secretVariables, _ := backend.HandleValues(sparseR1CS, values, []uint32{})

	assertIsBoolean(0, sparseR1CS)

	assertThatProvingFails(t, publicVariables, secretVariables, sparseR1CS)
}

func TestAssertIsEqualComponentWithEqualElements(t *testing.T) {
	values := fr_bn254.Vector{fr_bn254.NewElement(0), fr_bn254.One()}
	sparseR1CS := cs_bn254.NewSparseR1CS(1)

	publicVariables, secretVariables, _ := backend.HandleValues(sparseR1CS, values, []uint32{})

	// TODO: I think that there is a bug in Gnark here. If you want to see it for
	// yourself, just remove the second assertIsEqual. It seems that when having
	// one constraint that it's supposed to be satisfied when proving, an error
	// rises, and in the same case but with a constraint system that it is not
	// supposed to be satisfied the proving goes well (see that TestAssertIsEqualComponentWithNonEqualElements)
	// passes. This is the same for every other similar test.
	assertIsEqual(0, 0, sparseR1CS)
	assertIsEqual(1, 1, sparseR1CS)

	constraints, res := sparseR1CS.GetConstraints()
	for _, sparseR1C := range constraints {
		fmt.Println(sparseR1C.String(res))
	}

	assertThatProvingAndVerifyingSucceeds(t, publicVariables, secretVariables, sparseR1CS)
}

func TestAssertIsEqualComponentWithNonEqualElements(t *testing.T) {
	values := fr_bn254.Vector{fr_bn254.NewElement(2), fr_bn254.NewElement(3)}
	sparseR1CS := cs_bn254.NewSparseR1CS(1)

	publicVariables, secretVariables, _ := backend.HandleValues(sparseR1CS, values, []uint32{})

	assertIsEqual(0, 1, sparseR1CS)

	assertThatProvingFails(t, publicVariables, secretVariables, sparseR1CS)
}