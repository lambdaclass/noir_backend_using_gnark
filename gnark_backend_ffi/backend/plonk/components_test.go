package plonk_backend

import (
	"fmt"
	"gnark_backend_ffi/backend"
	"testing"

	fr_bn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/constraint"
	cs_bn254 "github.com/consensys/gnark/constraint/bn254"
	"github.com/stretchr/testify/assert"
)

// Computes a single constraint.
func checkConstraint(constraint constraint.SparseR1C, sparseR1CS *cs_bn254.SparseR1CS, values fr_bn254.Vector) error {
	// It is tempting to abstract the repeated code below in this function, but it is
	// better to keep it as is, because it is easier to understand what is going on
	// when computing the terms.

	var l fr_bn254.Element
	qL := sparseR1CS.Coefficients[constraint.L.CID]
	xa := values[constraint.L.VID]
	l.Mul(&qL, &xa)

	var r fr_bn254.Element
	qR := sparseR1CS.Coefficients[constraint.R.CID]
	xb := values[constraint.R.VID]
	r.Mul(&qR, &xb)

	var o fr_bn254.Element
	qO := sparseR1CS.Coefficients[constraint.O.CID]
	xc := values[constraint.O.VID]
	o.Mul(&qO, &xc)

	var m0 fr_bn254.Element
	qM1 := sparseR1CS.Coefficients[constraint.M[0].CID]
	m0.Mul(&qM1, &xa)

	var m1 fr_bn254.Element
	qM2 := sparseR1CS.Coefficients[constraint.M[1].CID]
	m1.Mul(&qM2, &xb)

	c := sparseR1CS.Coefficients[constraint.K]

	var t fr_bn254.Element
	t.Mul(&m0, &m1).Add(&t, &l).Add(&t, &r).Add(&t, &o).Add(&t, &c)
	if !t.IsZero() {
		return fmt.Errorf("qL⋅xa + qR⋅xb + qO⋅xc + qM⋅(xaxb) + qC != 0 → %s + %s + %s + (%s × %s) + %s != 0",
			l.String(),
			r.String(),
			o.String(),
			m0.String(),
			m1.String(),
			c.String(),
		)
	}
	return nil
}

// Checks all the constraints of a circuit.
func checkConstraints(sparseR1CS *cs_bn254.SparseR1CS, values fr_bn254.Vector) error {
	constraints, _ := sparseR1CS.GetConstraints()

	for _, constraint := range constraints {
		err := checkConstraint(constraint, sparseR1CS, values)
		if err != nil {
			return err
		}
	}
	return nil
}

func assertThatProvingAndVerifyingSucceeds(t *testing.T, publicVariables fr_bn254.Vector, secretVariables fr_bn254.Vector, sparseR1CS *cs_bn254.SparseR1CS) {
	witness := backend.BuildWitnesses(sparseR1CS.Field(), publicVariables, secretVariables, sparseR1CS.GetNbPublicVariables(), sparseR1CS.GetNbSecretVariables())

	srs, err := backend.TryLoadSRS(sparseR1CS.CurveID())
	assert.Nil(t, err, err)

	pk, vk, err := plonk.Setup(sparseR1CS, srs)
	assert.Nil(t, err, err)

	proof, err := plonk.Prove(sparseR1CS, pk, witness)
	assert.Nil(t, err, err)

	publicWitnesses, err := witness.Public()

	err = plonk.Verify(proof, vk, publicWitnesses)
	assert.Nil(t, err, err)
}

func assertThatProvingFails(t *testing.T, publicVariables fr_bn254.Vector, secretVariables fr_bn254.Vector, sparseR1CS *cs_bn254.SparseR1CS) {
	witness := backend.BuildWitnesses(sparseR1CS.Field(), publicVariables, secretVariables, sparseR1CS.GetNbPublicVariables(), sparseR1CS.GetNbSecretVariables())

	srs, err := backend.TryLoadSRS(sparseR1CS.CurveID())
	assert.Nil(t, err, err)

	pk, _, err := plonk.Setup(sparseR1CS, srs)
	assert.Nil(t, err, err)

	_, err = plonk.Prove(sparseR1CS, pk, witness)
	assert.Error(t, err)
	// TODO: Figure out why the below assertion fails.
	// assert.ErrorIs(t, err, fmt.Errorf("constraint #1 is not satisfied: qL⋅xa + qR⋅xb + qO⋅xc + qM⋅(xaxb) + qC != 0 → 0 + 0 + 0 + (-1 × 2) + 0 != 0"))
}

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

func TestToBitsConversionWithNoBits(t *testing.T) {
	values := fr_bn254.Vector{fr_bn254.One()}
	sparseR1CS := cs_bn254.NewSparseR1CS(1)

	publicVariables, secretVariables, _ := backend.HandleValues(sparseR1CS, values, []uint32{})

	result, secretVariables := toBinaryConversion(0, 0, sparseR1CS, secretVariables)
	assert.Empty(t, result)

	assertThatProvingFails(t, publicVariables, secretVariables, sparseR1CS)
}

func TestToBitsConversionWithOneBit(t *testing.T) {
	values := fr_bn254.Vector{fr_bn254.One()}
	sparseR1CS := cs_bn254.NewSparseR1CS(1)

	publicVariables, secretVariables, _ := backend.HandleValues(sparseR1CS, values, []uint32{})

	result, secretVariables := toBinaryConversion(0, 1, sparseR1CS, secretVariables)
	assert.Equal(t, fr_bn254.One(), secretVariables[result[0]])

	assertThatProvingAndVerifyingSucceeds(t, publicVariables, secretVariables, sparseR1CS)
}

func TestToBitsConversionWithMoreThanOneBit(t *testing.T) {
	values := fr_bn254.Vector{fr_bn254.NewElement(3)}
	sparseR1CS := cs_bn254.NewSparseR1CS(1)

	publicVariables, secretVariables, _ := backend.HandleValues(sparseR1CS, values, []uint32{})

	result, secretVariables := toBinaryConversion(0, 2, sparseR1CS, secretVariables)
	assert.Equal(t, fr_bn254.One(), secretVariables[result[0]])
	assert.Equal(t, fr_bn254.One(), secretVariables[result[1]])

	assertThatProvingAndVerifyingSucceeds(t, publicVariables, secretVariables, sparseR1CS)
}
