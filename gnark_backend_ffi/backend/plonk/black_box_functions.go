package plonk_backend

import (
	"gnark_backend_ffi/acir/opcode"
	"gnark_backend_ffi/backend/plonk/components"

	fr_bn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/constraint"
)

// AES black box function call is not handled
func AES() {}

func AND(bbf *opcode.BlackBoxFunction, sparseR1CS constraint.SparseR1CS, variables fr_bn254.Vector) (addedSecretVariables fr_bn254.Vector) {
	lhs := int(bbf.Inputs[0].Witness)
	rhs := int(bbf.Inputs[1].Witness)
	bits := int(bbf.Inputs[0].NumBits)

	_, addedSecretVariables, _ = components.And(lhs, rhs, bits, sparseR1CS, variables)
	return
}

func XOR(bbf *opcode.BlackBoxFunction, sparseR1CS constraint.SparseR1CS, variables fr_bn254.Vector) (addedSecretVariables fr_bn254.Vector) {
	lhs := int(bbf.Inputs[0].Witness)
	rhs := int(bbf.Inputs[1].Witness)
	bits := int(bbf.Inputs[0].NumBits)

	_, addedSecretVariables, _ = components.Xor(lhs, rhs, bits, sparseR1CS, variables)
	return
}

// RANGE black box function call is not handled
func Range() {}

// SHA256 black box function call is not handled
func SHA256() {}

// Blake2s black box function call is not handled
func Blake2s() {}

// MerkleMembership black box function call is not handled
func MerkleMembership() {}

// SchnorrVerify black box function call is not handled
func SchnorrVerify() {}

// Pedersen black box function call is not handled
func Pedersen() {}

// HashToField128Security black box function call is not handled
func HashToField128Security() {}

// EcdsaSecp256k1 black box function call is not handled
func EcdsaSecp256k1() {}

// FixedBaseScalarMul black box function call is not handled
func FixedBaseScalarMul() {}

// Keccak256 black box function call is not handled
func Keccak256() {}
