package main

import "C"
import (
	"bytes"
	"fmt"
	"log"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	cs_bls12381 "github.com/consensys/gnark/constraint/bls12-381"
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

//export Preprocess
func Preprocess(rawR1CS string) (*C.char, *C.char) {
	// Create R1CS.
	r1cs := cs_bls12381.NewR1CS(1)

	// Add variables.

	// Add constraints.

	// Setup.
	pk, vk, err := groth16.Setup(r1cs)
	if err != nil {
		log.Fatal(err)
	}

	// Serialize proving key.
	var serialized_pk bytes.Buffer
	pk.WriteTo(&serialized_pk)
	pk_string := serialized_pk.String()

	// Serialize verifying key.
	var serialized_vk bytes.Buffer
	vk.WriteTo(&serialized_vk)
	vk_string := serialized_vk.String()

	return C.CString(pk_string), C.CString(vk_string)
}

func main() {}
