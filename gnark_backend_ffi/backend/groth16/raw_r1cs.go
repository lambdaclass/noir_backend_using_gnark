package groth16

import (
	"encoding/json"
	"gnark_backend_ffi/backend"
	"log"

	fr_bn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

type RawR1CS struct {
	Gates          []RawGate
	PublicInputs   backend.Witnesses
	Values         fr_bn254.Vector
	NumVariables   uint64
	NumConstraints uint64
}

func (r *RawR1CS) UnmarshalJSON(data []byte) error {
	var rawR1CSMap map[string]interface{}
	err := json.Unmarshal(data, &rawR1CSMap)
	if err != nil {
		log.Print(err)
		return err
	}

	var gates []RawGate
	var publicInputs backend.Witnesses
	var values fr_bn254.Vector
	var numVariables uint64
	var numConstraints uint64

	// Deserialize gates.
	if gatesValue, ok := rawR1CSMap["gates"].([]interface{}); ok {
		gatesJSON, err := json.Marshal(gatesValue)
		if err != nil {
			log.Print(err)
			return err
		}
		err = json.Unmarshal(gatesJSON, &gates)
		if err != nil {
			log.Print(err)
			return err
		}
	} else {
		log.Print("Error: couldn't deserialize raw gates.")
		return &json.UnmarshalTypeError{}
	}

	if publicInputsValue, ok := rawR1CSMap["public_inputs"].([]interface{}); ok {
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

	// Deserialize values.
	if encodedValues, ok := rawR1CSMap["values"].(string); ok {
		values = backend.DeserializeFelts(encodedValues)
	} else {
		log.Print("Error: couldn't deserialize values.")
		return &json.UnmarshalTypeError{}
	}

	// Deserialize num_variables.
	if numVariablesValue, ok := rawR1CSMap["num_variables"].(float64); ok {
		numVariables = uint64(numVariablesValue)
	} else {
		log.Print("Error: couldn't deserialize num_variables.")
		return &json.UnmarshalTypeError{}
	}

	// Deserialize num_constraints.
	if numConstraintsValue, ok := rawR1CSMap["num_constraints"].(float64); ok {
		numConstraints = uint64(numConstraintsValue)
	} else {
		log.Print("Error: couldn't deserialize num_constraints.")
		return &json.UnmarshalTypeError{}
	}

	r.Gates = gates
	r.PublicInputs = publicInputs
	r.Values = values
	r.NumVariables = numVariables
	r.NumConstraints = numConstraints

	return nil
}
