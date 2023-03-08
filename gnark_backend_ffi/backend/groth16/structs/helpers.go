package structs

import (
	"encoding/json"
	"log"
)

func UncheckedDeserializeRawGate(rawGate string) RawGate {
	var r RawGate
	err := json.Unmarshal([]byte(rawGate), &r)
	if err != nil {
		log.Fatal(err)
	}

	return r
}

func UncheckedDeserializeRawGates(rawGates string) []RawGate {
	var r []RawGate
	err := json.Unmarshal([]byte(rawGates), &r)
	if err != nil {
		log.Fatal(err)
	}

	return r
}

func UncheckedDeserializeRawR1CS(rawR1CS string) RawR1CS {
	var r RawR1CS
	err := json.Unmarshal([]byte(rawR1CS), &r)
	if err != nil {
		log.Fatal(err)
	}

	return r
}
