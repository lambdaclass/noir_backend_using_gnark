package main

import "C"
import (
	"bytes"
	"fmt"
	"log"

	"github.com/consensys/gnark/backend/groth16"
	cs_bls12381 "github.com/consensys/gnark/constraint/bls12-381"
)

// TODO: Deserialize rawR1CS.

//export ProveWithMeta
func ProveWithMeta(rawR1CS string) *C.char {
	// Create R1CS.
	r1cs := cs_bls12381.NewR1CS(1)

	// Add variables.

	// Add constraints.

	// Setup.
	pk, _, err := groth16.Setup(r1cs)
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
