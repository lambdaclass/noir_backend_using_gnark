package plonk_backend

import (
	"fmt"
	"gnark_backend_ffi/backend"
	"log"
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

func TestAssertIsBooleanComponentWithBooleans(t *testing.T) {
	values := fr_bn254.Vector{fr_bn254.NewElement(0), fr_bn254.One()}
	sparseR1CS := cs_bn254.NewSparseR1CS(1)

	publicVariables, secretVariables, _ := backend.HandleValues(sparseR1CS, values, []uint32{})

	assertIsBoolean(0, sparseR1CS)
	assertIsBoolean(1, sparseR1CS)

	witness := backend.BuildWitnesses(sparseR1CS.Field(), publicVariables, secretVariables, sparseR1CS.GetNbPublicVariables(), sparseR1CS.GetNbSecretVariables())

	srs, err := backend.TryLoadSRS(sparseR1CS.CurveID())
	if err != nil {
		log.Fatal(err)
	}

	pk, vk, err := plonk.Setup(sparseR1CS, srs)
	if err != nil {
		log.Fatal(err)
	}

	proof, err := plonk.Prove(sparseR1CS, pk, witness)
	if err != nil {
		log.Fatal(err)
	}

	publicWitnesses, err := witness.Public()
	if err != nil {
		log.Fatal(err)
	}

	if plonk.Verify(proof, vk, publicWitnesses) != nil {
		log.Fatal(err)
	}

	assert.True(t, true)
}

func TestAssertIsBooleanComponentWithNonBooleans(t *testing.T) {
	values := fr_bn254.Vector{fr_bn254.NewElement(2)}
	sparseR1CS := cs_bn254.NewSparseR1CS(1)

	publicVariables, secretVariables, _ := backend.HandleValues(sparseR1CS, values, []uint32{})

	assertIsBoolean(0, sparseR1CS)

	witness := backend.BuildWitnesses(sparseR1CS.Field(), publicVariables, secretVariables, sparseR1CS.GetNbPublicVariables(), sparseR1CS.GetNbSecretVariables())

	srs, err := backend.TryLoadSRS(sparseR1CS.CurveID())
	assert.Nil(t, err)

	pk, _, err := plonk.Setup(sparseR1CS, srs)
	assert.Nil(t, err)

	_, err = plonk.Prove(sparseR1CS, pk, witness)
	assert.Error(t, err)
	// TODO: Figure out why the below assertion fails.
	// assert.ErrorIs(t, err, fmt.Errorf("constraint #1 is not satisfied: qL⋅xa + qR⋅xb + qO⋅xc + qM⋅(xaxb) + qC != 0 → 0 + 0 + 0 + (-1 × 2) + 0 != 0"))
}

func TestBitAndComponentWithBooleans(t *testing.T) {
	values := fr_bn254.Vector{fr_bn254.NewElement(0), fr_bn254.One()}
	sparseR1CS := cs_bn254.NewSparseR1CS(1)
	one := fr_bn254.One()
	zero := fr_bn254.NewElement(0)

	publicVariables, secretVariables, _ := backend.HandleValues(sparseR1CS, values, []uint32{})

	result, secretVariables := and(0, 0, sparseR1CS, secretVariables)
	assert.Equal(t, zero, secretVariables[result])
	result, secretVariables = and(0, 1, sparseR1CS, secretVariables)
	assert.Equal(t, zero, secretVariables[result])
	result, secretVariables = and(1, 0, sparseR1CS, secretVariables)
	assert.Equal(t, zero, secretVariables[result])
	result, secretVariables = and(1, 1, sparseR1CS, secretVariables)
	assert.Equal(t, one, secretVariables[result])

	witness := backend.BuildWitnesses(sparseR1CS.Field(), publicVariables, secretVariables, sparseR1CS.GetNbPublicVariables(), sparseR1CS.GetNbSecretVariables())

	srs, err := backend.TryLoadSRS(sparseR1CS.CurveID())
	assert.Nil(t, err)

	pk, vk, err := plonk.Setup(sparseR1CS, srs)
	assert.Nil(t, err)

	proof, err := plonk.Prove(sparseR1CS, pk, witness)
	assert.Nil(t, err)

	publicWitnesses, err := witness.Public()
	assert.Nil(t, err)

	if plonk.Verify(proof, vk, publicWitnesses) != nil {
		log.Fatal(err)
	}

	assert.True(t, true)
}

func TestBitAndComponentWithNonBooleans(t *testing.T) {
	values := fr_bn254.Vector{fr_bn254.NewElement(2), fr_bn254.NewElement(3)}
	sparseR1CS := cs_bn254.NewSparseR1CS(1)
	one := fr_bn254.One()
	zero := fr_bn254.NewElement(0)

	publicVariables, secretVariables, _ := backend.HandleValues(sparseR1CS, values, []uint32{})

	result, secretVariables := and(0, 0, sparseR1CS, secretVariables)
	assert.NotEqual(t, zero, secretVariables[result])
	assert.NotEqual(t, one, secretVariables[result])
	result, secretVariables = and(0, 1, sparseR1CS, secretVariables)
	assert.NotEqual(t, zero, secretVariables[result])
	assert.NotEqual(t, one, secretVariables[result])
	result, secretVariables = and(1, 0, sparseR1CS, secretVariables)
	assert.NotEqual(t, zero, secretVariables[result])
	assert.NotEqual(t, one, secretVariables[result])
	result, secretVariables = and(1, 1, sparseR1CS, secretVariables)
	assert.NotEqual(t, zero, secretVariables[result])
	assert.NotEqual(t, one, secretVariables[result])

	witness := backend.BuildWitnesses(sparseR1CS.Field(), publicVariables, secretVariables, sparseR1CS.GetNbPublicVariables(), sparseR1CS.GetNbSecretVariables())

	srs, err := backend.TryLoadSRS(sparseR1CS.CurveID())
	assert.Nil(t, err)

	pk, _, err := plonk.Setup(sparseR1CS, srs)
	assert.Nil(t, err)

	_, err = plonk.Prove(sparseR1CS, pk, witness)
	assert.Error(t, err)
}
