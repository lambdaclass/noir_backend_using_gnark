package plonk

import "gnark_backend_ffi/backend"

type BlackBoxFunctionName = int

const (
	AES BlackBoxFunctionName = iota
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

type BlackBoxFunction struct {
	Name    BlackBoxFunctionName
	Inputs  []FunctionInput
	Outputs backend.Witnesses
}
