package structs

type Opcode = int

const (
	Arithmetic Opcode = iota
	BlackBoxFunctionCall
	Directive
)

type OpcodeFields struct {
	Opcode               Opcode
	Arithmetic           GateTerms
	BlackBoxFunctionCall BlackBoxFunctionFields
	Directive            DirectiveFields
}
