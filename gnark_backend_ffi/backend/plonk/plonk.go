package plonk_backend

import (
	"gnark_backend_ffi/acir"
	"gnark_backend_ffi/backend"
	"log"

	fr_bn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/backend/plonk"
	cs_bn254 "github.com/consensys/gnark/constraint/bn254"
)

func Preprocess(acir acir.ACIR, values fr_bn254.Vector) (plonk.ProvingKey, plonk.VerifyingKey, error) {
	// Build sparse R1CS.
	sparseR1CS, _, _ := BuildSparseR1CS(acir, values)

	srs, err := backend.TryLoadSRS(sparseR1CS.CurveID())
	if err != nil {
		log.Fatal(err)
	}

	return plonk.Setup(sparseR1CS, srs)
}

func VerifyWithVK(sparseR1CS *cs_bn254.SparseR1CS,
	verifyingKey plonk.VerifyingKey,
	proof plonk.Proof,
	publicVariables fr_bn254.Vector,
	secretVariables fr_bn254.Vector) bool {
	// Setup.
	srs, err := backend.TryLoadSRS(sparseR1CS.CurveID())
	if err != nil {
		log.Fatal(err)
	}
	if verifyingKey.InitKZG(srs) != nil {
		log.Fatal(err)
	}
	// Build witness.
	witness := backend.BuildWitnesses(sparseR1CS.CurveID().ScalarField(), publicVariables, secretVariables, sparseR1CS.GetNbPublicVariables(), sparseR1CS.GetNbSecretVariables())

	// Retrieve public inputs.
	witnessPublics, err := witness.Public()
	if err != nil {
		log.Fatal(err)
	}

	// Verify.
	if plonk.Verify(proof, verifyingKey, witnessPublics) != nil {
		return false
	}

	return true
}

func ProveWithPK(circuit acir.ACIR, provingKey plonk.ProvingKey, values fr_bn254.Vector) (proof plonk.Proof) {
	sparseR1CS, publicVariables, secretVariables := BuildSparseR1CS(circuit, values)
	witness := backend.BuildWitnesses(sparseR1CS.CurveID().ScalarField(), publicVariables, secretVariables, sparseR1CS.GetNbPublicVariables(), sparseR1CS.GetNbSecretVariables())

	// Setup.
	srs, err := backend.TryLoadSRS(sparseR1CS.CurveID())
	if err != nil {
		log.Fatal(err)
	}
	if provingKey.InitKZG(srs) != nil {
		log.Fatal(err)
	}

	// Prove
	proof, err = plonk.Prove(sparseR1CS, provingKey, witness)
	if err != nil {
		log.Fatal(err)
	}

	return
}
