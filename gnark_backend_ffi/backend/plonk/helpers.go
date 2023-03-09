package plonk

import (
	"encoding/json"
	"log"
)

func UncheckedDeserializeOpcodes(opcodes string) []OpcodeUnpacker {
	var o []OpcodeUnpacker
	err := json.Unmarshal([]byte(opcodes), &o)
	if err != nil {
		log.Fatal(err)
	}

	return o
}
