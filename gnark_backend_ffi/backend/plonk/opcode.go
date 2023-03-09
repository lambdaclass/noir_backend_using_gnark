package plonk

import (
	"encoding/json"
)

type Opcode struct {
	Data interface{}
}

func (o *Opcode) UnmarshalJSON(b []byte) error {
	arithmetic_opcode := &ArithmeticOpcode{}
	err := json.Unmarshal(b, arithmetic_opcode)
	if err == nil {
		o.Data = arithmetic_opcode
		return nil
	}

	directive_opcode := &DirectiveOpcode{}
	err = json.Unmarshal(b, directive_opcode)
	if err == nil {
		o.Data = directive_opcode
		return nil
	}

	return err
}
