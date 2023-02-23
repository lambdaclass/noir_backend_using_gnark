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

//export ProveWithPK
func ProveWithPK(rawR1CS string, provingKey string) *C.char {
	// Create R1CS.
	r1cs := cs_bls12381.NewR1CS(1)

	// Add variables.

	// Add constraints.

	// Deserialize proving key.
	pk := groth16.NewProvingKey(r1cs.CurveID())
	_, err := pk.ReadFrom(bytes.NewReader([]byte(provingKey)))
	if err != nil {
		log.Fatal(err)
	}

	// Prove.
	proof, err := groth16.Prove(r1cs, pk, nil)
	if err != nil {
		log.Fatal(err)
	}

	// Serialize proof
	var serialized_proof bytes.Buffer
	proof.WriteTo(&serialized_proof)
	proof_string := serialized_proof.String()

	return C.CString(proof_string)
}

//export Verify
func Verify(rawr1cs string, proof string) bool {

	fmt.Printf("rawr1cs: %v\n", rawr1cs)
	fmt.Printf("proof: %v\n", proof)
	return false
}

func main() {}
