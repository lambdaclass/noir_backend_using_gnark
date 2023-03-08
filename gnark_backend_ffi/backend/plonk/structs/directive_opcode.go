package structs

import "gnark_backend_ffi/backend"

type DirectiveOpcode = int

const (
	// Inverts the value of x and stores it in the result variable
	Invert DirectiveOpcode = iota
)

type InvertFields struct {
	X      backend.Witness
	Result backend.Witness
}

type DirectiveFields struct {
	Opcode DirectiveOpcode
	Invert InvertFields
}
