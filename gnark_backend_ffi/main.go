package main

import "C"
import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"log"

	"gnark_backend_ffi/acir"
	"gnark_backend_ffi/backend"
	plonk_backend "gnark_backend_ffi/backend/plonk"
	backend_helpers "gnark_backend_ffi/internal/backend"

	"github.com/consensys/gnark-crypto/ecc"
	fr_bn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/kzg"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/constraint"
	cs_bn254 "github.com/consensys/gnark/constraint/bn254"
)

//export PlonkProveWithPK
func PlonkProveWithPK(acirJSON string, encodedValues string, encodedProvingKey string) *C.char {
	var circuit acir.ACIR
	err := json.Unmarshal([]byte(acirJSON), &circuit)
	if err != nil {
		log.Fatal(err)
	}
	values := backend_helpers.DeserializeFelts(encodedValues)
	provingKey := backend_helpers.DeserializeProvingKey(encodedProvingKey, ecc.BN254)

	proof := plonk_backend.ProveWithPK(circuit, provingKey, values, ecc.BN254)

	return C.CString(backend_helpers.SerializeProof(proof))
}

//export PlonkVerifyWithMeta
func PlonkVerifyWithMeta(acirJSON string, encodedValues string, encodedProof string) bool {
	return false
}

//export PlonkVerifyWithVK
func PlonkVerifyWithVK(acirJSON string, encodedProof string, encodedPublicInputs string, encodedVerifyingKey string) bool {
	var circuit acir.ACIR
	err := json.Unmarshal([]byte(acirJSON), &circuit)
	if err != nil {
		log.Fatal(err)
	}
	proof := backend_helpers.DeserializeProof(encodedProof, ecc.BN254)
	publicInputs := backend_helpers.DeserializeFelts(encodedPublicInputs)
	verifyingKey := backend_helpers.DeserializeVerifyingKey(encodedVerifyingKey, ecc.BN254)

	return plonk_backend.VerifyWithVK(circuit, verifyingKey, proof, publicInputs, ecc.BN254)
}

//export PlonkPreprocess
func PlonkPreprocess(acirJSON string, encodedRandomValues string) (*C.char, *C.char) {
	// Deserialize ACIR.
	var acir acir.ACIR
	err := json.Unmarshal([]byte(acirJSON), &acir)
	if err != nil {
		log.Fatal(err)
	}
	// Decode values.
	var valuesToDecode string
	err = json.Unmarshal([]byte(encodedRandomValues), &valuesToDecode)
	if err != nil {
		log.Fatal(err)
	}
	decodedRandomValues := backend_helpers.DeserializeFelts(valuesToDecode)

	provingKey, verifyingKey := plonk_backend.Preprocess(acir, decodedRandomValues)

	return C.CString(backend_helpers.SerializeProvingKey(provingKey)), C.CString(backend_helpers.SerializeVerifyingKey(verifyingKey))
}

func ExampleSimpleCircuit() {
	publicVariables := []fr_bn254.Element{fr_bn254.NewElement(2), fr_bn254.NewElement(6)}
	secretVariables := []fr_bn254.Element{fr_bn254.NewElement(3)}

	/* R1CS Building */

	fmt.Println("Building R1CS...")
	// x * y == z
	// x is secret
	// y is public
	r1cs := cs_bn254.NewR1CS(1)

	// Variables
	_ = r1cs.AddPublicVariable("1") // the ONE_WIRE
	Y := r1cs.AddPublicVariable("Y")
	Z := r1cs.AddPublicVariable("Z")
	X := r1cs.AddSecretVariable("X")

	// Coefficients
	cOne := r1cs.FromInterface(1)

	// Constraints
	fmt.Println("Adding constraints...")
	r1cs.AddConstraint(constraint.R1C{
		L: constraint.LinearExpression{r1cs.MakeTerm(&cOne, X)},
		R: constraint.LinearExpression{r1cs.MakeTerm(&cOne, Y)},
		O: constraint.LinearExpression{r1cs.MakeTerm(&cOne, Z)},
	})
	fmt.Println("Constraints added.")
	fmt.Println("R1CS built.")

	constraints, r := r1cs.GetConstraints()

	for _, r1c := range constraints {
		fmt.Println(r1c.String(r))
	}

	/* Universal SRS Generation */

	fmt.Println("Generating SRS...")

	pk, vk, _ := groth16.Setup(r1cs)

	fmt.Println("SRS generated.")

	/* Proving */

	fmt.Println("Proving...")

	witness := backend.BuildWitnesses(r1cs.CurveID().ScalarField(), publicVariables, secretVariables, r1cs.GetNbPublicVariables()-1, r1cs.GetNbSecretVariables())

	p, _ := groth16.Prove(r1cs, pk, witness)

	fmt.Println("Proof generated.")

	/* Verification */

	fmt.Println("Verifying...")

	publicWitness, _ := witness.Public()

	verifies := groth16.Verify(p, vk, publicWitness)

	fmt.Println("Verifies:", verifies == nil)
}

func PlonkExample(acirJSON string, values fr_bn254.Vector) {
	fmt.Println("Deserializing ACIR...")
	var a acir.ACIR
	err := json.Unmarshal([]byte(acirJSON), &a)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("ACIR deserialized.")
	fmt.Println()

	fmt.Println("Building Sparse R1CS...")
	sparseR1CS, publicVariables, secretVariables := plonk_backend.BuildSparseR1CS(a, values)
	fmt.Println("Sparse R1CS built.")
	fmt.Println("Constraints:")
	constraints, res := sparseR1CS.GetConstraints()
	for _, sparseR1C := range constraints {
		fmt.Println(sparseR1C.String(res))
	}
	fmt.Println()

	fmt.Println("Building witness...")
	witness := backend.BuildWitnesses(sparseR1CS.CurveID().ScalarField(), publicVariables, secretVariables, sparseR1CS.GetNbPublicVariables(), sparseR1CS.GetNbSecretVariables())
	fmt.Println("Witness built.")
	fmt.Println()

	fmt.Println("Setting up...")
	alpha, err := rand.Int(rand.Reader, sparseR1CS.CurveID().ScalarField())
	if err != nil {
		log.Fatal(err)
	}
	srs, err := kzg.NewSRS(128, alpha)
	if err != nil {
		log.Fatal(err)
	}
	pk, vk, err := plonk.Setup(sparseR1CS, srs)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Setup done.")
	fmt.Println()

	fmt.Println("Building proof...")
	proof, err := plonk.Prove(sparseR1CS, pk, witness)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Proof built.")
	fmt.Println()

	fmt.Println("Verifying proof...")
	publicWitnesses, err := witness.Public()
	fmt.Println("Public witness:", publicWitnesses.Vector().(fr_bn254.Vector).String())
	fmt.Println("Witness:", witness.Vector().(fr_bn254.Vector).String())
	if err != nil {
		log.Fatal(err)
	}
	verifies := plonk.Verify(proof, vk, publicWitnesses)
	fmt.Println("Verifies with valid public inputs:", verifies == nil)
	fmt.Println()

	// err = json.Unmarshal([]byte(invalidACIR), &a)
	// if err != nil {
	// 	log.Fatal(err)
	// }

	// invalidSparseR1CS, publicVariables, secretVariables := buildSparseR1CS(a, values)
	// invalidWitness := common.BuildWitnesses(invalidSparseR1CS.CurveID().ScalarField(), publicVariables, secretVariables, invalidSparseR1CS.GetNbPublicVariables(), invalidSparseR1CS.GetNbSecretVariables())
	// invalidPublicWitnesses, _ := invalidWitness.Public()
	// invalidVerified := plonk.Verify(proof, vk, invalidPublicWitnesses)

	// fmt.Println("Valid Public Witnesses: ", publicWitnesses.Vector().(fr_bn254.Vector).String())
	// fmt.Println("Invalid Public Witnesses: ", invalidPublicWitnesses.Vector().(fr_bn254.Vector).String())
	// fmt.Println()

	// fmt.Println("Verifies with invalid public inputs: ", invalidVerified == nil)
}

func main() {
	zero := fr_bn254.NewElement(0)
	one := fr_bn254.One()
	two := fr_bn254.NewElement(2)
	var minusOne fr_bn254.Element
	minusOne.Sub(&zero, &one)

	// 0 != 1
	PlonkExample(
		`{"current_witness_index":6,"opcodes":[{"Arithmetic":{"mul_terms":[],"linear_combinations":[["0000000000000000000000000000000000000000000000000000000000000001",1],["30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000000",2],["30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000000",3]],"q_c":"0000000000000000000000000000000000000000000000000000000000000000"}},{"Directive":{"Invert":{"x":3,"result":4}}},{"Arithmetic":{"mul_terms":[["0000000000000000000000000000000000000000000000000000000000000001",3,4]],"linear_combinations":[["30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000000",5]],"q_c":"0000000000000000000000000000000000000000000000000000000000000000"}},{"Arithmetic":{"mul_terms":[["0000000000000000000000000000000000000000000000000000000000000001",3,5]],"linear_combinations":[["30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000000",3]],"q_c":"0000000000000000000000000000000000000000000000000000000000000000"}},{"Arithmetic":{"mul_terms":[],"linear_combinations":[["30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000000",5]],"q_c":"0000000000000000000000000000000000000000000000000000000000000001"}}],"public_inputs":[2]}`,
		fr_bn254.Vector{zero, one, minusOne, minusOne, one, zero},
	)

	// 2 == 2
	PlonkExample(
		`{"current_witness_index":6,"opcodes":[{"Arithmetic":{"mul_terms":[],"linear_combinations":[["0000000000000000000000000000000000000000000000000000000000000001",1],["30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000000",2],["30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000000",3]],"q_c":"0000000000000000000000000000000000000000000000000000000000000000"}},{"Directive":{"Invert":{"x":3,"result":4}}},{"Arithmetic":{"mul_terms":[["0000000000000000000000000000000000000000000000000000000000000001",3,4]],"linear_combinations":[["30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000000",5]],"q_c":"0000000000000000000000000000000000000000000000000000000000000000"}},{"Arithmetic":{"mul_terms":[["0000000000000000000000000000000000000000000000000000000000000001",3,5]],"linear_combinations":[["30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000000",3]],"q_c":"0000000000000000000000000000000000000000000000000000000000000000"}},{"Arithmetic":{"mul_terms":[],"linear_combinations":[["0000000000000000000000000000000000000000000000000000000000000001",5]],"q_c":"0000000000000000000000000000000000000000000000000000000000000000"}}],"public_inputs":[2]}`,
		fr_bn254.Vector{two, two, zero, zero, zero, zero},
	)
}
