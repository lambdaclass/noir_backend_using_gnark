package opcode

// DirectiveOpcode is an empty struct because Directives are handled by the
// PartialWitnessGenerator trait implementation in the Rust backend side.
// Nevertheless, Directive opcodes objects come in the ACIR JSON and we need to
// handle them. So this struct exists for serialization purposes.
type DirectiveOpcode struct{}
