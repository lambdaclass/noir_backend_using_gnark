package plonk_backend

import (
	"gnark_backend_ffi/acir"
	"gnark_backend_ffi/backend"
	"log"

	"github.com/consensys/gnark-crypto/ecc"
	fr_bn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/backend/plonk"
)

func Preprocess(acir acir.ACIR, values fr_bn254.Vector) (pk plonk.ProvingKey, vk plonk.VerifyingKey) {
	sparseR1CS, _, _ := BuildSparseR1CS(acir, values)

	srs, err := backend.TryLoadSRS(sparseR1CS.CurveID())
	if err != nil {
		log.Fatal(err)
	}

	pk, vk, err = plonk.Setup(sparseR1CS, srs)
	if err != nil {
		log.Fatal(err)
	}

	return
}

func VerifyWithVK(circuit acir.ACIR, verifyingKey plonk.VerifyingKey, proof plonk.Proof, publicVariables fr_bn254.Vector, curveID ecc.ID) bool {
	sparseR1CS, publicVariables, secretVariables := BuildSparseR1CS(circuit, publicVariables)
	witness := backend.BuildWitnesses(curveID.ScalarField(), publicVariables, secretVariables, sparseR1CS.GetNbPublicVariables(), sparseR1CS.GetNbSecretVariables())

	// Setup.
	srs, err := backend.TryLoadSRS(curveID)
	if err != nil {
		log.Fatal(err)
	}
	if verifyingKey.InitKZG(srs) != nil {
		log.Fatal(err)
	}

	// Verify.
	witnessPublics, err := witness.Public()
	if err != nil {
		log.Fatal(err)
	}
	if plonk.Verify(proof, verifyingKey, witnessPublics) != nil {
		return false
	}
	return true
}

func ProveWithPK(circuit acir.ACIR, provingKey plonk.ProvingKey, values fr_bn254.Vector, curveID ecc.ID) (proof plonk.Proof) {
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
