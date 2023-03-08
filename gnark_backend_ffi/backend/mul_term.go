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
	var mul_term_map map[string]interface{}
	err := json.Unmarshal(data, &mul_term_map)
	if err != nil {
		log.Fatal(err)
		return err
	}

	var coefficient fr_bn254.Element
	var multiplicand Witness
	var multiplier Witness

	// Deserialize coefficient.
	if encodedCoefficient, ok := mul_term_map["coefficient"].(string); ok {
		coefficient = DeserializeFelt(encodedCoefficient)
	} else {
		log.Fatal("Error: couldn't deserialize coefficient.")
		return &json.UnmarshalTypeError{}
	}

	// Deserialize multiplicand.
	if m, ok := mul_term_map["multiplicand"].(float64); ok {
		multiplicand = Witness(m)
	} else {
		log.Fatal("Error: couldn't deserialize multiplicand.")
		return &json.UnmarshalTypeError{}
	}

	// Deserialize multiplier.
	if m, ok := mul_term_map["multiplier"].(float64); ok {
		multiplier = Witness(m)
	} else {
		log.Fatal("Error: couldn't deserialize multiplier.")
		return &json.UnmarshalTypeError{}
	}

	m.Coefficient = coefficient
	m.Multiplicand = multiplicand
	m.Multiplier = multiplier

	return nil
}
