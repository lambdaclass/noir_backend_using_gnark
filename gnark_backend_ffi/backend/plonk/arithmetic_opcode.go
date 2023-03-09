package groth16

import (
	"encoding/json"
	"gnark_backend_ffi/backend"
	"log"

	fr_bn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

type ArithmeticOpcode struct {
	MulTerms []backend.MulTerm
	AddTerms []backend.AddTerm
	QC       fr_bn254.Element
}

func (g *ArithmeticOpcode) UnmarshalJSON(data []byte) error {
	var opcodeMap map[string]interface{}
	var gateMap map[string]interface{}
	err := json.Unmarshal(data, &opcodeMap)
	if err != nil {
		log.Print(err)
		return err
	}

	if gateValue, ok := opcodeMap["Arithmetic"]; ok {
		gateJSON, err := json.Marshal(gateValue)
		if err != nil {
			log.Print(err)
			return err
		}
		err = json.Unmarshal(gateJSON, &gateMap)
		if err != nil {
			log.Print(err)
			return err
		}
	} else {
		log.Print("Error: couldn't deserialize gate.")
		return &json.UnmarshalTypeError{}
	}

	var mulTerms []backend.MulTerm
	var addTerms []backend.AddTerm
	var constantTerm fr_bn254.Element

	// Deserialize mul terms.
	if mulTermsValue, ok := gateMap["mul_terms"].([]interface{}); ok {
		mulTermsJSON, err := json.Marshal(mulTermsValue)
		if err != nil {
			log.Print(err)
			return err
		}
		err = json.Unmarshal(mulTermsJSON, &mulTerms)
		if err != nil {
			log.Print(err)
			return err
		}
	} else {
		log.Print("Error: couldn't deserialize mul terms.")
		return &json.UnmarshalTypeError{}
	}

	// Deserialize add terms.
	if addTermsValue, ok := gateMap["linear_combinations"].([]interface{}); ok {
		addTermsJSON, err := json.Marshal(addTermsValue)
		if err != nil {
			log.Print(err)
			return err
		}
		err = json.Unmarshal(addTermsJSON, &addTerms)
		if err != nil {
			log.Print(err)
			return err
		}
	} else {
		log.Print("Error: couldn't deserialize add terms.")
		return &json.UnmarshalTypeError{}
	}

	// Deserialize constant term.
	if encodedConstantTerm, ok := gateMap["q_c"].(string); ok {
		constantTerm = backend.DeserializeFelt(encodedConstantTerm)
	} else {
		log.Print("Error: coefficient is not a felt.")
		return &json.UnmarshalTypeError{}
	}

	g.MulTerms = mulTerms
	g.AddTerms = addTerms
	g.QC = constantTerm

	return nil
}
