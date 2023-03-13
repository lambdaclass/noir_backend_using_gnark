package term

import (
	"encoding/json"
	"log"

	common "gnark_backend_ffi/internal"
	backend_helpers "gnark_backend_ffi/internal/backend"

	fr_bn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

type MulTerms = []MulTerm

type MulTerm struct {
	Coefficient       fr_bn254.Element
	MultiplicandIndex common.Witness
	MultiplierIndex   common.Witness
}

func (m *MulTerm) UnmarshalJSON(data []byte) error {
	var mulTerm []interface{}
	err := json.Unmarshal(data, &mulTerm)
	if err != nil {
		log.Print(err)
		return err
	}

	var coefficient fr_bn254.Element
	var multiplicand common.Witness
	var multiplier common.Witness

	// Deserialize coefficient.
	if coefficientValue, ok := mulTerm[0].(string); ok {
		coefficient = backend_helpers.DeserializeFelt(coefficientValue)
	} else {
		log.Print("Error: couldn't deserialize coefficient.")
		return &json.UnmarshalTypeError{}
	}

	// Deserialize multiplicand.
	if multiplicandValue, ok := mulTerm[1].(float64); ok {
		multiplicand = common.Witness(multiplicandValue)
	} else {
		log.Print("Error: couldn't deserialize multiplicand.")
		return &json.UnmarshalTypeError{}
	}

	// Deserialize multiplier.
	if multiplierValue, ok := mulTerm[2].(float64); ok {
		multiplier = common.Witness(multiplierValue)
	} else {
		log.Print("Error: couldn't deserialize multiplier.")
		return &json.UnmarshalTypeError{}
	}

	m.Coefficient = coefficient
	m.MultiplicandIndex = multiplicand
	m.MultiplierIndex = multiplier

	return nil
}
