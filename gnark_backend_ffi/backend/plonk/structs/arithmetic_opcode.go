package structs

import (
	"gnark_backend_ffi/backend"

	fr_bn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

type GateTerms struct {
	MulTerms []backend.MulTerm
	AddTerms []backend.AddTerm
	qM       fr_bn254.Element
}
