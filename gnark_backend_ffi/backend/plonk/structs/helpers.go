package structs

import (
	"encoding/json"
	"log"
)

func UncheckedDeserializeOpcodes(opcodes string) []Opcode {
	var o []Opcode
	err := json.Unmarshal([]byte(opcodes), &o)
	if err != nil {
		log.Fatal(err)
	}

	return o
}
