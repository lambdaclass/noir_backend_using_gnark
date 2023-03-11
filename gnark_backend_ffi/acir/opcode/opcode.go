package opcode

import (
	"encoding/json"
)

type Opcode struct {
	Data interface{}
}

// An opcode is either an Arithmetic opcode, a BlackBoxFunction opcode or a
// Directive opcode.
func (o *Opcode) UnmarshalJSON(b []byte) error {
	arithmetic_opcode := &ArithmeticOpcode{}
	err := json.Unmarshal(b, arithmetic_opcode)
	if err == nil {
		o.Data = arithmetic_opcode
		return nil
	}

	// TODO: Implement UnmarshalJSON for BlackBoxFunction.
	// blackBoxFunctionOpcode := &BlackBoxFunction{}
	// err = json.Unmarshal(b, blackBoxFunctionOpcode)
	// if err == nil {
	// 	o.Data = blackBoxFunctionOpcode
	// 	return nil
	// }

	o.Data = &DirectiveOpcode{}
	return nil
}
