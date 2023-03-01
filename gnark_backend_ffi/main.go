package main

import "C"
import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"strconv"

	"gnark_backend_ffi/structs"

	fr_bn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
	cs_bn254 "github.com/consensys/gnark/constraint/bn254"
)

func buildR1CS(r structs.RawR1CS) (*cs_bn254.R1CS, fr_bn254.Vector, fr_bn254.Vector, int, int) {
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
		for _, publicInput := range r.PublicInputs {
			if uint32(i) == publicInput {
				allVariableIndices = append(allVariableIndices, r1cs.AddPublicVariable(variableName))
				publicVariables = append(publicVariables, value)
				nPublicVariables++
			} else {
				allVariableIndices = append(allVariableIndices, r1cs.AddSecretVariable(variableName))
				privateVariables = append(privateVariables, value)
				nPrivateVariables++
			}
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
	var r structs.RawR1CS
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

//export TestFeltSerialization
func TestFeltSerialization(encodedFelt string) *C.char {
	deserializedFelt := structs.DeserializeFelt(encodedFelt)
	fmt.Printf("| GO |\n%v\n", deserializedFelt)

	// Serialize the felt.
	serializedFelt := deserializedFelt.Bytes()

	// Encode the serialized felt.
	serializedFeltString := hex.EncodeToString(serializedFelt[:])

	return C.CString(serializedFeltString)
}

//export TestFeltsSerialization
func TestFeltsSerialization(encodedFelts string) *C.char {
	deserializedFelts := structs.DeserializeFelts(encodedFelts)

	// Serialize the felt.
	serializedFelts, err := deserializedFelts.MarshalBinary()
	if err != nil {
		log.Fatal(err)
	}

	// Encode the serialized felt.
	serializedFeltsString := hex.EncodeToString(serializedFelts[:])

	return C.CString(serializedFeltsString)
}

//export TestU64Serialization
func TestU64Serialization(number uint64) uint64 {
	fmt.Println(number)
	return number
}

//export TestMulTermSerialization
func TestMulTermSerialization(mulTermJSON string) *C.char {
	var deserializedMulTerm structs.MulTerm
	err := json.Unmarshal([]byte(mulTermJSON), &deserializedMulTerm)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("| GO |")
	fmt.Println("", deserializedMulTerm.Coefficient)
	fmt.Println("", deserializedMulTerm.Multiplicand)
	fmt.Println("", deserializedMulTerm.Multiplier)

	serializedMulTerm, err := json.Marshal(deserializedMulTerm)
	if err != nil {
		log.Fatal(err)
	}

	return C.CString(string(serializedMulTerm))
}

//export TestMulTermsSerialization
func TestMulTermsSerialization(mulTermsJSON string) *C.char {
	var deserializedMulTerms []structs.MulTerm
	err := json.Unmarshal([]byte(mulTermsJSON), &deserializedMulTerms)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("| GO |")
	for _, deserializedMulTerm := range deserializedMulTerms {
		fmt.Println("", deserializedMulTerm.Coefficient)
		fmt.Println("", deserializedMulTerm.Multiplicand)
		fmt.Println("", deserializedMulTerm.Multiplier)
		fmt.Println()
	}

	serializedMulTerms, err := json.Marshal(deserializedMulTerms)
	if err != nil {
		log.Fatal(err)
	}

	return C.CString(string(serializedMulTerms))
}

//export TestAddTermSerialization
func TestAddTermSerialization(addTermJSON string) *C.char {
	var deserializedAddTerm structs.AddTerm
	err := json.Unmarshal([]byte(addTermJSON), &deserializedAddTerm)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("| GO |")
	fmt.Println("", deserializedAddTerm.Coefficient)
	fmt.Println("", deserializedAddTerm.Sum)

	serializedAddTerm, err := json.Marshal(deserializedAddTerm)
	if err != nil {
		log.Fatal(err)
	}

	return C.CString(string(serializedAddTerm))
}

//export TestAddTermsSerialization
func TestAddTermsSerialization(addTermsJSON string) *C.char {
	var deserializedAddTerms []structs.AddTerm
	err := json.Unmarshal([]byte(addTermsJSON), &deserializedAddTerms)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("| GO |")
	for _, deserializedAddTerm := range deserializedAddTerms {
		fmt.Println("", deserializedAddTerm.Coefficient)
		fmt.Println("", deserializedAddTerm.Sum)
		fmt.Println()
	}

	serializedAddTerms, err := json.Marshal(deserializedAddTerms)
	if err != nil {
		log.Fatal(err)
	}

	return C.CString(string(serializedAddTerms))
}

//export TestRawGateSerialization
func TestRawGateSerialization(rawGateJSON string) *C.char {
	var deserializedRawGate structs.RawGate
	err := json.Unmarshal([]byte(rawGateJSON), &deserializedRawGate)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("| GO |")
	fmt.Println("", deserializedRawGate.MulTerms)
	fmt.Println("", deserializedRawGate.AddTerms)
	fmt.Println("", deserializedRawGate.ConstantTerm)
	fmt.Println()

	serializedRawGate, err := json.Marshal(deserializedRawGate)
	if err != nil {
		log.Fatal(err)
	}

	return C.CString(string(serializedRawGate))
}

//export TestRawGatesSerialization
func TestRawGatesSerialization(rawGatesJSON string) *C.char {
	var deserializedRawGates []structs.RawGate
	err := json.Unmarshal([]byte(rawGatesJSON), &deserializedRawGates)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("| GO |")
	for _, deserializedRawGate := range deserializedRawGates {
		fmt.Println("", deserializedRawGate.MulTerms)
		fmt.Println("", deserializedRawGate.AddTerms)
		fmt.Println("", deserializedRawGate.ConstantTerm)
		fmt.Println()
	}

	serializedRawGate, err := json.Marshal(deserializedRawGates)
	if err != nil {
		log.Fatal(err)
	}

	return C.CString(string(serializedRawGate))
}

//export TestRawR1CSSerialization
func TestRawR1CSSerialization(rawR1CSJSON string) *C.char {
	var deserializedRawR1CS structs.RawR1CS
	err := json.Unmarshal([]byte(rawR1CSJSON), &deserializedRawR1CS)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("| GO |")
	fmt.Println("Gates: ", deserializedRawR1CS.Gates)
	fmt.Println("Public inputs: ", deserializedRawR1CS.PublicInputs)
	fmt.Println("Values: ", deserializedRawR1CS.Values)
	fmt.Println("Number of variables: ", deserializedRawR1CS.NumVariables)
	fmt.Println("Number of constraints: ", deserializedRawR1CS.NumConstraints)
	fmt.Println()

	serializedRawR1CS, err := json.Marshal(deserializedRawR1CS)
	if err != nil {
		log.Fatal(err)
	}

	return C.CString(string(serializedRawR1CS))
}

func main() {}
