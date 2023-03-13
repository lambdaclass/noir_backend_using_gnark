package plonk_backend

import (
	"gnark_backend_ffi/acir"
	"gnark_backend_ffi/backend"
	"log"

	fr_bn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/backend/plonk"
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
