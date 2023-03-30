package plonk_backend

import (
	acir_opcode "gnark_backend_ffi/acir/opcode"
	"gnark_backend_ffi/backend"
)

// AES black box function call is not handled
func AES() {}

func AND(ctx *backend.Context, bbf *acir_opcode.BlackBoxFunction) {
	lhs := int(bbf.Inputs[0].Witness)
	rhs := int(bbf.Inputs[1].Witness)
	bits := int(bbf.Inputs[0].NumBits)

	And(lhs, rhs, bits, ctx)
}

func XOR(ctx *backend.Context, bbf *acir_opcode.BlackBoxFunction) {
	lhs := int(bbf.Inputs[0].Witness)
	rhs := int(bbf.Inputs[1].Witness)
	bits := int(bbf.Inputs[0].NumBits)

	Xor(lhs, rhs, bits, ctx)
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
