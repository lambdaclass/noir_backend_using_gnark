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

//export VerifyWithVK
func VerifyWithVK(rawr1cs string, proof string, verifyingKey string) bool {
	// Create R1CS.
	r1cs := cs_bls12381.NewR1CS(1)

	// Add variables.

	// Add constraints.

	// Deserialize proof.
	p := groth16.NewProof(r1cs.CurveID())
	_, err_p := p.ReadFrom(bytes.NewReader([]byte(proof)))
	if err_p != nil {
		log.Fatal(err_p)
	}

	// Deserialize verifying key.
	vk := groth16.NewVerifyingKey(r1cs.CurveID())
	_, err_vk := vk.ReadFrom(bytes.NewReader([]byte(verifyingKey)))
	if err_vk != nil {
		log.Fatal(err_vk)
	}

	// Verify.
	if groth16.Verify(p, vk, nil) != nil {
		return false
	}

	return true
}

func main() {}
