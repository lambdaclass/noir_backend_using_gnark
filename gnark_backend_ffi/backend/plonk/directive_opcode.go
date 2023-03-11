package plonk

import (
	"encoding/json"
	"gnark_backend_ffi/backend"
	"log"
)

type DirectiveName = int

const (
	Invert DirectiveName = iota
	ToRadix
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
		return err
	}

	var X backend.Witness
	var Result backend.Witness

	// Deserialize X.
	if XValue, ok := invertDirectiveMap["x"].(float64); ok {
		X = backend.Witness(XValue)
	} else {
		log.Print("Error: couldn't deserialize X.")
		return &json.UnmarshalTypeError{}
	}

	// Deserialize Result.
	if ResultValue, ok := invertDirectiveMap["result"].(float64); ok {
		Result = backend.Witness(ResultValue)
	} else {
		log.Print("Error: couldn't deserialize Result.")
		return &json.UnmarshalTypeError{}
	}

	d.X = X
	d.Result = Result

	return nil
}

type ToRadixDirective struct {
	A              ArithmeticOpcode
	B              []backend.Witness
	Radix          uint32
	IsLittleEndian bool
}

func (d *ToRadixDirective) UnmarshalJSON(data []byte) error {
	var invertDirectiveMap map[string]interface{}
	err := json.Unmarshal(data, &invertDirectiveMap)
	if err != nil {
		return err
	}

	var A ArithmeticOpcode
	var B []backend.Witness
	var Radix uint32
	var IsLittleEndian bool
	/*
		// Deserialize Radix.
		if RadixValue, ok := invertDirectiveMap["radix"].(float64); ok {
			Radix = uint32(RadixValue)
		} else {
			log.Print("Error: couldn't deserialize Radix.")
			return &json.UnmarshalTypeError{}
		}

		// Deserialize Radix.
		if IsLittleEndianValue, ok := invertDirectiveMap["is_little_endian"].(float64); ok {
			IsLittleEndian = bool(IsLittleEndianValue)
		} else {
			log.Print("Error: couldn't deserialize X.")
			return &json.UnmarshalTypeError{}
		}

		// Deserialize Result.
		if BValue, ok := invertDirectiveMap["b"].(float64); ok {
			Result = backend.Witness(ResultValue)
		} else {
			log.Fatal("Error: couldn't deserialize Result.")
			return &json.UnmarshalTypeError{}
		}
	*/
	d.A = A
	d.B = B
	d.Radix = Radix
	d.IsLittleEndian = IsLittleEndian

	return nil
}

func (d *DirectiveOpcode) UnmarshalJSON(data []byte) error {
	var directiveMap map[string]interface{}
	err := json.Unmarshal(data, &directiveMap)
	if err != nil {
		log.Fatal(err)
		return err
	}

	if directiveValue, ok := directiveMap["Directive"].(map[string]interface{}); ok {
		if invertDirectiveValue, ok := directiveValue["Invert"]; ok {
			var dir InvertDirective
			invertDirectiveJSON, err := json.Marshal(invertDirectiveValue)
			if err != nil {
				return err
			}
			err = json.Unmarshal(invertDirectiveJSON, &dir)
			if err != nil {
				return err
			}
			d.Name = Invert
			d.Directive = dir
		} else if toRadixDirectiveValue, ok := directiveValue["ToRadix"]; ok {
			var dir ToRadixDirective
			toRadixDirectiveJSON, err := json.Marshal(toRadixDirectiveValue)
			if err != nil {
				return err
			}
			err = json.Unmarshal(toRadixDirectiveJSON, &dir)
			if err != nil {
				return err
			}
			d.Name = ToRadix
			d.Directive = dir
		} else {
			return &json.UnmarshalTypeError{}
		}
	}

	return nil
}
