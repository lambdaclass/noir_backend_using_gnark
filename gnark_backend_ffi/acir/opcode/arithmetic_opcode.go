package opcode

import (
	"encoding/json"

	"gnark_backend_ffi/acir/term"
	backend_helpers "gnark_backend_ffi/internal/backend"

	fr_bn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

type ArithmeticOpcode struct {
	MulTerms    term.MulTerms
	SimpleTerms term.SimpleTerms
	QC          fr_bn254.Element
}

func (g *ArithmeticOpcode) UnmarshalJSON(data []byte) error {
	var opcodeMap map[string]interface{}
	err := json.Unmarshal(data, &opcodeMap)
	if err != nil {
		return err
	}

	var gateMap map[string]interface{}
	if gateValue, ok := opcodeMap["Arithmetic"]; ok {
		gateJSON, err := json.Marshal(gateValue)
		if err != nil {
			return err
		}
		err = json.Unmarshal(gateJSON, &gateMap)
		if err != nil {
			return err
		}
	} else {
		return &json.UnmarshalTypeError{}
	}

	var mulTerms term.MulTerms
	var addTerms term.SimpleTerms
	var constantTerm fr_bn254.Element

	// Deserialize mul terms.
	if mulTermsValue, ok := gateMap["mul_terms"].([]interface{}); ok {
		mulTermsJSON, err := json.Marshal(mulTermsValue)
		if err != nil {
			return err
		}
		err = json.Unmarshal(mulTermsJSON, &mulTerms)
		if err != nil {
			return err
		}
	} else {
		return &json.UnmarshalTypeError{}
	}

	// Deserialize add terms.
	if addTermsValue, ok := gateMap["linear_combinations"].([]interface{}); ok {
		addTermsJSON, err := json.Marshal(addTermsValue)
		if err != nil {
			return err
		}
		err = json.Unmarshal(addTermsJSON, &addTerms)
		if err != nil {
			return err
		}
	} else {
		return &json.UnmarshalTypeError{}
	}

	// Deserialize constant term.
	if encodedConstantTerm, ok := gateMap["q_c"].(string); ok {
		constantTerm = backend_helpers.DeserializeFelt(encodedConstantTerm)
	} else {
		return &json.UnmarshalTypeError{}
	}

	g.MulTerms = mulTerms
	g.SimpleTerms = addTerms
	g.QC = constantTerm

	return nil
}
