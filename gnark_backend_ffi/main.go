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

//export VerifyWithMeta
func VerifyWithMeta(rawr1cs string, proof string) bool {
	// Create R1CS.
	r1cs := cs_bls12381.NewR1CS(1)

	// Add variables.

	// Add constraints.

	// Deserialize proof.
	p := groth16.NewProof(r1cs.CurveID())
	_, err := p.ReadFrom(bytes.NewReader([]byte(proof)))
	if err != nil {
		log.Fatal(err)
	}

	// Setup.
	_, vk, err := groth16.Setup(r1cs)
	if err != nil {
		log.Fatal(err)
	}

	// Verify.
	if groth16.Verify(p, vk, nil) != nil {
		return false
	}

	return true
}

func main() {}
