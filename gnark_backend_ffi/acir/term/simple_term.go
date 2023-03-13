package term

import (
	"encoding/json"
	"log"

	common "gnark_backend_ffi/internal"
	backend_helpers "gnark_backend_ffi/internal/backend"

	fr_bn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

type SimpleTerms = []SimpleTerm

type SimpleTerm struct {
	Coefficient   fr_bn254.Element
	VariableIndex common.Witness
}

func (m *SimpleTerm) UnmarshalJSON(data []byte) error {
	var linearTerm []interface{}
	err := json.Unmarshal(data, &linearTerm)
	if err != nil {
		log.Print(err)
		return err
	}

	var coefficient fr_bn254.Element
	var variable common.Witness

	// Deserialize coefficient.
	if coefficientValue, ok := linearTerm[0].(string); ok {
		coefficient = backend_helpers.DeserializeFelt(coefficientValue)
	} else {
		log.Print("Error: couldn't deserialize coefficient.")
		return &json.UnmarshalTypeError{}
	}

	// Deserialize sum.
	if variableIndex, ok := linearTerm[1].(float64); ok {
		variable = common.Witness(variableIndex)
	} else {
		log.Print("Error: couldn't deserialize x.")
		return &json.UnmarshalTypeError{}
	}

	m.Coefficient = coefficient
	m.VariableIndex = variable

	return nil
}
