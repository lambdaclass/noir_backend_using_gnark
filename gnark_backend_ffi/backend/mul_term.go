package backend

import (
	"encoding/json"
	"log"

	fr_bn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

type MulTerm struct {
	Coefficient  fr_bn254.Element
	Multiplicand Witness
	Multiplier   Witness
}

func (m *MulTerm) UnmarshalJSON(data []byte) error {
	var mulTerm []interface{}
	err := json.Unmarshal(data, &mulTerm)
	if err != nil {
		log.Print(err)
		return err
	}

	var coefficient fr_bn254.Element
	var multiplicand Witness
	var multiplier Witness

	// Deserialize coefficient.
	if coefficientValue, ok := mulTerm[0].(string); ok {
		coefficient = DeserializeFelt(coefficientValue)
	} else {
		log.Print("Error: couldn't deserialize coefficient.")
		return &json.UnmarshalTypeError{}
	}

	// Deserialize multiplicand.
	if multiplicandValue, ok := mulTerm[1].(float64); ok {
		multiplicand = Witness(multiplicandValue)
	} else {
		log.Print("Error: couldn't deserialize multiplicand.")
		return &json.UnmarshalTypeError{}
	}

	// Deserialize multiplier.
	if multiplierValue, ok := mulTerm[2].(float64); ok {
		multiplier = Witness(multiplierValue)
	} else {
		log.Print("Error: couldn't deserialize multiplier.")
		return &json.UnmarshalTypeError{}
	}

	m.Coefficient = coefficient
	m.Multiplicand = multiplicand
	m.Multiplier = multiplier

	return nil
}
