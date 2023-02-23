package main

import "C"
import (
	"bytes"
	"fmt"
	"unsafe"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
)

//export Prove
func Prove(rawr1cs string) unsafe.Pointer {

	fmt.Printf("rawr1cs: %v\n", rawr1cs)

	var serialized_proof bytes.Buffer

	proof := groth16.NewProof(ecc.BLS12_381)

	proof.WriteRawTo(&serialized_proof)

	return C.CBytes(serialized_proof.Bytes())
}

//export Verify
func Verify() bool {
	return false
}

func main() {}
