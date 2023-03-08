package groth16

import (
	"encoding/json"
	"gnark_backend_ffi/backend"
	"log"

	fr_bn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

type RawGate struct {
	MulTerms     []backend.MulTerm
	AddTerms     []backend.AddTerm
	ConstantTerm fr_bn254.Element
}

func (g *RawGate) UnmarshalJSON(data []byte) error {
	var rawGateMap map[string]interface{}
	err := json.Unmarshal(data, &rawGateMap)
	if err != nil {
		log.Fatal(err)
		return err
	}

	var mulTerms []backend.MulTerm
	var addTerms []backend.AddTerm
	var constantTerm fr_bn254.Element

	// Deserialize mul terms.
	if mulTermsValue, ok := rawGateMap["mul_terms"].([]interface{}); ok {
		mulTermsJSON, err := json.Marshal(mulTermsValue)
		if err != nil {
			log.Fatal(err)
			return err
		}
		err = json.Unmarshal(mulTermsJSON, &mulTerms)
		if err != nil {
			log.Fatal(err)
			return err
		}
	} else {
		log.Fatal("Error: couldn't deserialize mul terms.")
		return &json.UnmarshalTypeError{}
	}

	// Deserialize add terms.
	if addTermsValue, ok := rawGateMap["add_terms"].([]interface{}); ok {
		addTermsJSON, err := json.Marshal(addTermsValue)
		if err != nil {
			log.Fatal(err)
			return err
		}
		err = json.Unmarshal(addTermsJSON, &addTerms)
		if err != nil {
			log.Fatal(err)
			return err
		}
	} else {
		log.Fatal("Error: couldn't deserialize add terms.")
		return &json.UnmarshalTypeError{}
	}

	// Deserialize constant term.
	if encodedConstantTerm, ok := rawGateMap["constant_term"].(string); ok {
		constantTerm = backend.DeserializeFelt(encodedConstantTerm)
	} else {
		log.Fatal("Error: coefficient is not a felt.")
		return &json.UnmarshalTypeError{}
	}

	g.MulTerms = mulTerms
	g.AddTerms = addTerms
	g.ConstantTerm = constantTerm

	return nil
}
