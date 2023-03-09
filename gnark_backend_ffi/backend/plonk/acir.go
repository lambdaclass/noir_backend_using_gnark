package plonk

import (
	"encoding/json"
	"gnark_backend_ffi/backend"
	"log"
)

type ACIR struct {
	CurrentWitness backend.Witness
	Opcodes        []Opcode
	PublicInputs   backend.Witnesses
}

func (a *ACIR) UnmarshalJSON(data []byte) error {
	var acirMap map[string]interface{}
	err := json.Unmarshal(data, &acirMap)
	if err != nil {
		log.Print(err)
		return err
	}

	var opcodes []Opcode
	var publicInputs backend.Witnesses
	var currentWitness uint32

	if opcodesValue, ok := acirMap["opcodes"].([]interface{}); ok {
		opcodesJSON, err := json.Marshal(opcodesValue)
		if err != nil {
			log.Print(err)
			return err
		}

		err = json.Unmarshal(opcodesJSON, &opcodes)

		if err != nil {
			log.Print(err)
			return err
		}
	} else {
		log.Print("Error: couldn't deserialize opcodes.")
		return &json.UnmarshalTypeError{}
	}

	if publicInputsValue, ok := acirMap["public_inputs"].([]interface{}); ok {
		publicInputsJSON, err := json.Marshal(publicInputsValue)
		if err != nil {
			log.Print(err)
			return err
		}
		err = json.Unmarshal(publicInputsJSON, &publicInputs)
		if err != nil {
			log.Print(err)
			return err
		}
	} else {
		log.Print("Error: couldn't deserialize public inputs.")
		return &json.UnmarshalTypeError{}
	}

	if currentWitnessValue, ok := acirMap["current_witness_index"].(float64); ok {
		currentWitness = uint32(currentWitnessValue)
	} else {
		log.Print("Error: couldn't deserialize current witness.")
		return &json.UnmarshalTypeError{}
	}

	a.CurrentWitness = currentWitness
	a.Opcodes = opcodes
	a.PublicInputs = publicInputs

	return nil
}
