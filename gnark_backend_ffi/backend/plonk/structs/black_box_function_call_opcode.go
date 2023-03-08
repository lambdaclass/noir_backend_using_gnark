package structs

import "gnark_backend_ffi/backend"

type BlackBoxFunction = int

const (
	AES BlackBoxFunction = iota
	AND
	XOR
	RANGE
	SHA256
	Blake2s
	MerkleMembership
	SchnorrVerify
	Pedersen
	// 128 here specifies that this function
	// should have 128 bits of security
	HashToField128Security
	EcdsaSecp256k1
	FixedBaseScalarMul
	Keccak256
)

type FunctionInput struct {
	Witness backend.Witness
	NumBits uint32
}

type BlackBoxFunctionFields struct {
	Opcode  Opcode
	Name    BlackBoxFunction
	Inputs  []FunctionInput
	Outputs backend.Witnesses
}
