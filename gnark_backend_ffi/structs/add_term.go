package structs

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
	var add_term_map map[string]interface{}
	err := json.Unmarshal(data, &add_term_map)
	if err != nil {
		log.Print(err)
		return err
	}

	var coefficient fr_bn254.Element
	var sum Witness

	// Deserialize coefficient.
	if encodedCoefficient, ok := add_term_map["coefficient"].(string); ok {
		coefficient = DeserializeFelt(encodedCoefficient)
	} else {
		log.Print("Error: couldn't deserialize coefficient.")
		return &json.UnmarshalTypeError{}
	}

	// Deserialize sum.
	if m, ok := add_term_map["sum"].(float64); ok {
		sum = Witness(m)
	} else {
		log.Print("Error: couldn't deserialize sum.")
		return &json.UnmarshalTypeError{}
	}

	m.Coefficient = coefficient
	m.Sum = sum

	return nil
}
