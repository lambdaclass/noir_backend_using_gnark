package main

import "C"
import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"strconv"

	"github.com/recoilme/btreeset"

	fr_bn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
	cs_bn254 "github.com/consensys/gnark/constraint/bn254"
)

// TODO: Deserialize rawR1CS.

type RawR1CS struct {
	Gates          []RawGate
	PublicInputs   btreeset.BTreeSet
	Values         fr_bn254.Vector
	NumVariables   uint
	NumConstraints uint
}

type RawGate struct {
	MulTerms     []MulTerm
	AddTerms     []AddTerm
	ConstantTerm fr_bn254.Element
}

type MulTerm struct {
	Coefficient  fr_bn254.Element
	Multiplicand uint32
	Multiplier   uint32
}

type AddTerm struct {
	Coefficient fr_bn254.Element
	Sum         uint32
}

func buildR1CS(r RawR1CS) (*cs_bn254.R1CS, fr_bn254.Vector, fr_bn254.Vector, int, int) {
	// Create R1CS.
	r1cs := cs_bn254.NewR1CS(int(r.NumConstraints))

	// Fill process RawR1CS.
	nPublicVariables := 0
	nPrivateVariables := 0
	var allVariableIndices []int
	var publicVariables fr_bn254.Vector
	var privateVariables fr_bn254.Vector
	for i, value := range r.Values {
		variableName := strconv.Itoa(i)
		if r.PublicInputs.Has(make([]byte, i)) {
			allVariableIndices = append(allVariableIndices, r1cs.AddPublicVariable(variableName))
			publicVariables = append(publicVariables, value)
			nPublicVariables++
		} else {
			allVariableIndices = append(allVariableIndices, r1cs.AddSecretVariable(variableName))
			privateVariables = append(privateVariables, value)
			nPrivateVariables++
		}
	}

	// Generate constraints.
	ONE := r1cs.AddPublicVariable("ONE")
	ZERO := r1cs.AddPublicVariable("ZERO")
	COEFFICIENT_ONE := r1cs.FromInterface(1)
	for _, gate := range r.Gates {
		var terms constraint.LinearExpression

		for _, mul_term := range gate.MulTerms {
			coefficient := r1cs.FromInterface(mul_term.Coefficient)

			product := mul_term.Multiplicand * mul_term.Multiplier
			productVariableName := strconv.FormatUint(uint64(product), 10)
			productVariable := r1cs.AddSecretVariable(productVariableName)

			terms = append(terms, r1cs.MakeTerm(&coefficient, productVariable))
		}

		for _, add_term := range gate.AddTerms {
			coefficient := r1cs.FromInterface(add_term.Coefficient)
			sum := add_term.Sum

			sumVariable := allVariableIndices[sum]

			terms = append(terms, r1cs.MakeTerm(&coefficient, sumVariable))
		}

		r1cs.AddConstraint(
			constraint.R1C{
				L: constraint.LinearExpression{r1cs.MakeTerm(&COEFFICIENT_ONE, ONE)},
				R: terms,
				O: constraint.LinearExpression{r1cs.MakeTerm(&COEFFICIENT_ONE, ZERO)},
			},
		)
	}

	return r1cs, publicVariables, privateVariables, nPublicVariables, nPrivateVariables
}

func buildWitnesses(r1cs *cs_bn254.R1CS, publicVariables fr_bn254.Vector, privateVariables fr_bn254.Vector, nPublicVariables int, nPrivateVariables int) witness.Witness {
	witnessValues := make(chan any)

	go func() {
		defer close(witnessValues)
		for _, publicVariable := range publicVariables {
			witnessValues <- publicVariable
		}
		for _, privateVariable := range privateVariables {
			witnessValues <- privateVariable
		}
	}()

	witness, err := witness.New(r1cs.CurveID().ScalarField())
	if err != nil {
		log.Fatal(err)
	}

	witness.Fill(nPublicVariables, nPrivateVariables, witnessValues)

	return witness
}

//export ProveWithMeta
func ProveWithMeta(rawR1CS string) *C.char {
	// Deserialize rawR1CS.
	var r RawR1CS
	err := json.Unmarshal([]byte(rawR1CS), &r)
	if err != nil {
		log.Fatal(err)
	}

	r1cs, publicVariables, privateVariables, nPublicVariables, nPrivateVariables := buildR1CS(r)

	witness := buildWitnesses(r1cs, publicVariables, privateVariables, nPublicVariables, nPrivateVariables)

	// Setup.
	pk, _, err := groth16.Setup(r1cs)
	if err != nil {
		log.Fatal(err)
	}

	// Prove.
	proof, err := groth16.Prove(r1cs, pk, witness)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Proof: ", proof)

	// Serialize proof
	var serialized_proof bytes.Buffer
	proof.WriteTo(&serialized_proof)
	proof_string := serialized_proof.String()

	return C.CString(proof_string)
}

//export ProveWithPK
func ProveWithPK(rawR1CS string, provingKey string) *C.char {
	// Create R1CS.
	r1cs := cs_bn254.NewR1CS(1)

	// Add variables.
	witness, err := witness.New(r1cs.CurveID().ScalarField())
	if err != nil {
		log.Fatal(err)
	}
	witness.Fill(0, 0, nil)

	// Add constraints.

	// Deserialize proving key.
	pk := groth16.NewProvingKey(r1cs.CurveID())
	_, err = pk.ReadFrom(bytes.NewReader([]byte(provingKey)))
	if err != nil {
		log.Fatal(err)
	}

	// Prove.
	proof, err := groth16.Prove(r1cs, pk, witness)
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
	r1cs := cs_bn254.NewR1CS(1)

	// Add variables.
	witness, err := witness.New(r1cs.CurveID().ScalarField())
	if err != nil {
		log.Fatal(err)
	}
	witness.Fill(0, 0, nil)

	// Add constraints.

	// Deserialize proof.
	p := groth16.NewProof(r1cs.CurveID())
	_, err = p.ReadFrom(bytes.NewReader([]byte(proof)))
	if err != nil {
		log.Fatal(err)
	}

	// Setup.
	_, vk, err := groth16.Setup(r1cs)
	if err != nil {
		log.Fatal(err)
	}

	// Retrieve public inputs.
	publicInputs, err := witness.Public()
	if err != nil {
		log.Fatal(err)
	}

	// Verify.
	if groth16.Verify(p, vk, publicInputs) != nil {
		return false
	}

	return true
}

//export VerifyWithVK
func VerifyWithVK(rawr1cs string, proof string, verifyingKey string) bool {
	// Create R1CS.
	r1cs := cs_bn254.NewR1CS(1)

	// Add variables.
	witness, err := witness.New(r1cs.CurveID().ScalarField())
	if err != nil {
		log.Fatal(err)
	}
	witness.Fill(0, 0, nil)

	// Add constraints.

	// Deserialize proof.
	p := groth16.NewProof(r1cs.CurveID())
	_, err = p.ReadFrom(bytes.NewReader([]byte(proof)))
	if err != nil {
		log.Fatal(err)
	}

	// Deserialize verifying key.
	vk := groth16.NewVerifyingKey(r1cs.CurveID())
	_, err = vk.ReadFrom(bytes.NewReader([]byte(verifyingKey)))
	if err != nil {
		log.Fatal(err)
	}

	// Retrieve public inputs.
	publicInputs, err := witness.Public()
	if err != nil {
		log.Fatal(err)
	}

	// Verify.
	if groth16.Verify(p, vk, publicInputs) != nil {
		return false
	}

	return true
}

//export Preprocess
func Preprocess(rawR1CS string) (*C.char, *C.char) {
	// Create R1CS.
	r1cs := cs_bn254.NewR1CS(1)

	// Add variables.
	witness, err := witness.New(r1cs.CurveID().ScalarField())
	if err != nil {
		log.Fatal(err)
	}
	witness.Fill(0, 0, nil)

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

func main() {
	// rawR1CS := `{"gates":[{"mul_terms":[["0100000000000000000000000000000000000000000000000000000000000000",1],["000000f093f5e1439170b97948e833285d588181b64550b829a031e1724e6430",2],["000000f093f5e1439170b97948e833285d588181b64550b829a031e1724e6430",3]],"add_terms":[["0100000000000000000000000000000000000000000000000000000000000000",1],["000000f093f5e1439170b97948e833285d588181b64550b829a031e1724e6430",2],["000000f093f5e1439170b97948e833285d588181b64550b829a031e1724e6430",3]],"constant_term":"0000000000000000000000000000000000000000000000000000000000000000"},{"mul_terms":[["000000f093f5e1439170b97948e833285d588181b64550b829a031e1724e6430",5]],"add_terms":[["000000f093f5e1439170b97948e833285d588181b64550b829a031e1724e6430",5]],"constant_term":"0000000000000000000000000000000000000000000000000000000000000000"},{"mul_terms":[["000000f093f5e1439170b97948e833285d588181b64550b829a031e1724e6430",3]],"add_terms":[["000000f093f5e1439170b97948e833285d588181b64550b829a031e1724e6430",3]],"constant_term":"0000000000000000000000000000000000000000000000000000000000000000"},{"mul_terms":[["000000f093f5e1439170b97948e833285d588181b64550b829a031e1724e6430",5]],"add_terms":[["000000f093f5e1439170b97948e833285d588181b64550b829a031e1724e6430",5]],"constant_term":"0100000000000000000000000000000000000000000000000000000000000000"}],"public_inputs":[2],"values":["0100000000000000000000000000000000000000000000000000000000000000","0200000000000000000000000000000000000000000000000000000000000000","0000000000000000000000000000000000000000000000000000000000000000","0000000000000000000000000000000000000000000000000000000000000000","0000000000000000000000000000000000000000000000000000000000000000","0000000000000000000000000000000000000000000000000000000000000000"],"num_variables":7}`
	rawR1CS := `{"gates":[{"mul_terms":[["0100000000000000000000000000000000000000000000000000000000000000",1],["000000f093f5e1439170b97948e833285d588181b64550b829a031e1724e6430",2],["000000f093f5e1439170b97948e833285d588181b64550b829a031e1724e6430",3]],"add_terms":[["0100000000000000000000000000000000000000000000000000000000000000",1],["000000f093f5e1439170b97948e833285d588181b64550b829a031e1724e6430",2],["000000f093f5e1439170b97948e833285d588181b64550b829a031e1724e6430",3]],"constant_term":"0000000000000000000000000000000000000000000000000000000000000000"},{"mul_terms":[["000000f093f5e1439170b97948e833285d588181b64550b829a031e1724e6430",5]],"add_terms":[["000000f093f5e1439170b97948e833285d588181b64550b829a031e1724e6430",5]],"constant_term":"0000000000000000000000000000000000000000000000000000000000000000"},{"mul_terms":[["000000f093f5e1439170b97948e833285d588181b64550b829a031e1724e6430",3]],"add_terms":[["000000f093f5e1439170b97948e833285d588181b64550b829a031e1724e6430",3]],"constant_term":"0000000000000000000000000000000000000000000000000000000000000000"},{"mul_terms":[["000000f093f5e1439170b97948e833285d588181b64550b829a031e1724e6430",5]],"add_terms":[["000000f093f5e1439170b97948e833285d588181b64550b829a031e1724e6430",5]],"constant_term":"0100000000000000000000000000000000000000000000000000000000000000"}],"public_inputs":[2],"values":[[1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],[2,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]],"num_variables":7}`

	// Deserialize rawR1CS.
	var r RawR1CS
	err := json.Unmarshal([]byte(rawR1CS), &r)
	if err != nil {
		log.Fatal(err)
	}

	r1cs, publicVariables, privateVariables, nPublicVariables, nPrivateVariables := buildR1CS(r)

	fmt.Println("R1CS: ", r1cs)
	fmt.Println("Public Variables: ", publicVariables)
	fmt.Println("Private Variables: ", privateVariables)
	fmt.Println("Number of Public Variables: ", nPublicVariables)
	fmt.Println("Number of Private Variables: ", nPrivateVariables)

	// get the constraints
	constraints, resolver := r1cs.GetConstraints()

	for _, r1c := range constraints {
		fmt.Println(r1c.String(resolver))
		// for more granularity use constraint.NewStringBuilder(resolver) that embeds a string.Builder
		// and has WriteLinearExpression and WriteTerm methods.
	}

	// proof := ProveWithMeta(rawR1CS)

	// fmt.Println("Proof: ", proof)
}
