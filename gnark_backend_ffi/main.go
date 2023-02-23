package main

import "C"
import (
	"bytes"
	"fmt"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
)

//export Prove
func Prove(rawr1cs string) *C.char {

	fmt.Printf("rawr1cs: %v\n", rawr1cs)

	var serialized_proof bytes.Buffer

	proof := groth16.NewProof(ecc.BLS12_381)

	proof.WriteRawTo(&serialized_proof)

	return C.CString(rawr1cs)
}

//export Verify
func Verify(rawr1cs string, proof string) bool {

	fmt.Printf("rawr1cs: %v\n", rawr1cs)
	fmt.Printf("proof: %v\n", proof)
	return false
}

func main() {}
