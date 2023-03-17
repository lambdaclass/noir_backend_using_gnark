package opcode

import (
	"encoding/json"
	common "gnark_backend_ffi/internal"
)

type BlackBoxFunctionName = int

const (
	AES BlackBoxFunctionName = iota
	AND
	XOR
	RANGE
	SHA256
	Blake2s
	MerkleMembership
	SchnorrVerify
	Pedersen
	// 128 here specifies that this function
	// should have 128 bits of security
	HashToField128Security
	EcdsaSecp256k1
	FixedBaseScalarMul
	Keccak256
)

var (
	blackBoxFunctionsNameMap = map[string]BlackBoxFunctionName{
		"AES":                    AES,
		"AND":                    AND,
		"XOR":                    XOR,
		"RANGE":                  RANGE,
		"SHA256":                 SHA256,
		"Blake2s":                Blake2s,
		"MerkleMembership":       MerkleMembership,
		"SchnorrVerify":          SchnorrVerify,
		"Pedersen":               Pedersen,
		"HashToField128Security": HashToField128Security,
		"EcdsaSecp256k1":         EcdsaSecp256k1,
		"FixedBaseScalarMul":     FixedBaseScalarMul,
		"Keccak256":              Keccak256,
	}
)

type BlackBoxFunction struct {
	Name    BlackBoxFunctionName
	Inputs  FunctionInputs
	Outputs common.Witnesses
}

type FunctionInputs = []FunctionInput

type FunctionInput struct {
	Witness common.Witness
	NumBits uint32
}

func (bbf *BlackBoxFunction) UnmarshalJSON(data []byte) error {
	var opcodeMap map[string]interface{}
	err := json.Unmarshal(data, &opcodeMap)
	if err != nil {
		return err
	}

	var blackBoxFunctionMap map[string]interface{}
	if blackBoxFunctionValue, ok := opcodeMap["BlackBoxFunction"]; ok {
		blackBoxFunctionJSON, err := json.Marshal(blackBoxFunctionValue)
		if err != nil {
			return err
		}
		err = json.Unmarshal(blackBoxFunctionJSON, &blackBoxFunctionMap)
		if err != nil {
			return err
		}
	} else {
		return &json.UnmarshalTypeError{}
	}

	var name BlackBoxFunctionName
	var inputs FunctionInputs
	var outputs common.Witnesses

	if inputsValue, ok := blackBoxFunctionMap["inputs"].([]interface{}); ok {
		functionInputsJSON, err := json.Marshal(inputsValue)
		if err != nil {
			return err
		}
		err = json.Unmarshal(functionInputsJSON, &inputs)
		if err != nil {
			return err
		}
	} else {
		return &json.UnmarshalTypeError{}
	}

	if nameValue, ok := blackBoxFunctionMap["name"].(string); ok {
		name = blackBoxFunctionsNameMap[nameValue]
	} else {
		return &json.UnmarshalTypeError{}
	}

	if outputsValue, ok := blackBoxFunctionMap["outputs"].([]interface{}); ok {
		outputsJSON, err := json.Marshal(outputsValue)
		if err != nil {
			return err
		}
		err = json.Unmarshal(outputsJSON, &outputs)
		if err != nil {
			return err
		}
	} else {
		return &json.UnmarshalTypeError{}
	}

	bbf.Name = name
	bbf.Inputs = inputs
	bbf.Outputs = outputs

	return nil
}

func (fi *FunctionInput) UnmarshalJSON(data []byte) error {
	var functionInputMap map[string]interface{}
	err := json.Unmarshal(data, &functionInputMap)
	if err != nil {
		return err
	}

	var witness common.Witness
	var numBits uint32

	if witnessValue, ok := functionInputMap["witness"].(float64); ok {
		witness = common.Witness(witnessValue)
	} else {
		return &json.UnmarshalTypeError{}
	}

	if numBitsValue, ok := functionInputMap["num_bits"].(float64); ok {
		numBits = uint32(numBitsValue)
	} else {
		return &json.UnmarshalTypeError{}
	}

	fi.Witness = witness
	fi.NumBits = numBits

	return nil
}
