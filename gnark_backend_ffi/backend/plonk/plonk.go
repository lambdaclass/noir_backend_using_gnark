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

func VerifyWithVK(sparseR1CS *cs_bn254.SparseR1CS, verifyingKey plonk.VerifyingKey, proof plonk.Proof, publicVariables fr_bn254.Vector, secretVariables fr_bn254.Vector) bool {
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
