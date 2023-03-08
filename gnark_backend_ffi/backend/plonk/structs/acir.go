package structs

import "gnark_backend_ffi/backend"

type ACIR struct {
	CurrentWitness uint32
	Opcodes        []Opcode
	PublicInputs   backend.Witnesses
}
