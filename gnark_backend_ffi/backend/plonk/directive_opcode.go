package groth16

import (
	"encoding/json"
	"gnark_backend_ffi/backend"
	"log"
)

type DirectiveName = int

const (
	Invert DirectiveName = iota
)

type DirectiveOpcode struct {
	Name      DirectiveName
	Directive Directive
}

type Directive interface{}

type InvertDirective struct {
	X      backend.Witness
	Result backend.Witness
}

func (d *InvertDirective) UnmarshalJSON(data []byte) error {
	var invertDirectiveMap map[string]interface{}
	err := json.Unmarshal(data, &invertDirectiveMap)
	if err != nil {
		log.Print(err)
		return err
	}

	var X backend.Witness
	var Result backend.Witness

	// Deserialize X.
	if XValue, ok := invertDirectiveMap["x"].(float64); ok {
		X = backend.Witness(XValue)
	} else {
		log.Fatal("Error: couldn't deserialize X.")
		return &json.UnmarshalTypeError{}
	}

	// Deserialize Result.
	if ResultValue, ok := invertDirectiveMap["result"].(float64); ok {
		Result = backend.Witness(ResultValue)
	} else {
		log.Fatal("Error: couldn't deserialize Result.")
		return &json.UnmarshalTypeError{}
	}

	d.X = X
	d.Result = Result

	return nil
}

func (d *DirectiveOpcode) UnmarshalJSON(data []byte) error {
	var directiveMap map[string]interface{}
	err := json.Unmarshal(data, &directiveMap)
	if err != nil {
		log.Fatal(err)
		return err
	}

	if invertDirectiveValue, ok := directiveMap["Invert"]; ok {
		var dir InvertDirective
		invertDirectiveJSON, err := json.Marshal(invertDirectiveValue)
		if err != nil {
			log.Print(err)
			return err
		}
		err = json.Unmarshal(invertDirectiveJSON, &dir)
		if err != nil {
			log.Print(err)
			return err
		}
		d.Name = Invert
		d.Directive = dir
	} else {
		log.Print("Error: couldn't deserialize directive.")
		return &json.UnmarshalTypeError{}
	}

	return nil
}
