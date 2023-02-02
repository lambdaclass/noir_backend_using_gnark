package main

import "C"
import (
	"bytes"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
)

//export prove
func prove() []byte {
	var serialized_proof bytes.Buffer

	proof := groth16.NewProof(ecc.BLS12_381)

	proof.WriteRawTo(&serialized_proof)

	return serialized_proof.Bytes()
}

//export verify
func verify() bool {
	return false
}

func main() {}
