package backend

import (
	"encoding/json"
	"log"

	fr_bn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

type AddTerm struct {
	Coefficient fr_bn254.Element
	Sum         Witness
}

func (m *AddTerm) UnmarshalJSON(data []byte) error {
	var addTerm []interface{}
	err := json.Unmarshal(data, &addTerm)
	if err != nil {
		log.Print(err)
		return err
	}

	var coefficient fr_bn254.Element
	var x Witness

	// Deserialize coefficient.
	if coefficientValue, ok := addTerm[0].(string); ok {
		coefficient = DeserializeFelt(coefficientValue)
	} else {
		log.Print("Error: couldn't deserialize coefficient.")
		return &json.UnmarshalTypeError{}
	}

	// Deserialize sum.
	if xValue, ok := addTerm[1].(float64); ok {
		x = Witness(xValue)
	} else {
		log.Print("Error: couldn't deserialize x.")
		return &json.UnmarshalTypeError{}
	}

	m.Coefficient = coefficient
	m.Sum = x

	return nil
}
