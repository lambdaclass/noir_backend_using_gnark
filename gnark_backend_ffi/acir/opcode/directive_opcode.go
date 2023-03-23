package opcode

import "encoding/json"

// DirectiveOpcode is an empty struct because Directives are handled by the
// PartialWitnessGenerator trait implementation in the Rust backend side.
// Nevertheless, Directive opcodes objects come in the ACIR JSON and we need to
// handle them. So this struct exists for serialization purposes.
type DirectiveOpcode struct{}

// This implementation exists with the only purpose of ensuring that valid
// Directive opcodes are being skipped and not invalid opcodes (without this
// implementation this could happen because we'd be handling only Arithmetic
// and BlackBoxFunction opcodes and every invalid opcode would pass as a
// Directive one).
func (d *DirectiveOpcode) UnmarshalJSON(data []byte) error {
	var opcodeMap map[string]interface{}
	err := json.Unmarshal(data, &opcodeMap)
	if err != nil {
		return err
	}

	if _, ok := opcodeMap["Directive"]; ok {
		return nil
	}

	return &json.UnmarshalTypeError{}
}
