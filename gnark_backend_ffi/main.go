package main

import "C"
import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"

	"gnark_backend_ffi/structs"

	fr_bn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
	cs_bn254 "github.com/consensys/gnark/constraint/bn254"
)

func buildR1CS(r structs.RawR1CS) (*cs_bn254.R1CS, fr_bn254.Vector, fr_bn254.Vector) {
	// Create R1CS.
	r1cs := cs_bn254.NewR1CS(int(r.NumConstraints))

	// Define the R1CS variables.
	ONE := r1cs.AddPublicVariable("1")
	var publicVariables fr_bn254.Vector
	var privateVariables fr_bn254.Vector
	for i, value := range r.Values {
		i++
		for _, publicInput := range r.PublicInputs {
			if uint32(i) == publicInput {
				r1cs.AddPublicVariable(fmt.Sprintf("public_%d", i))
				publicVariables = append(publicVariables, value)
			} else {
				r1cs.AddSecretVariable(fmt.Sprintf("secret_%d", i))
				privateVariables = append(privateVariables, value)
			}
		}
	}

	// Generate constraints.
	COEFFICIENT_ONE := r1cs.FromInterface(1)
	for _, gate := range r.Gates {
		var terms constraint.LinearExpression

		for _, mul_term := range gate.MulTerms {
			coefficient := r1cs.FromInterface(mul_term.Coefficient)
			multiplicand := r.Values[mul_term.Multiplicand]
			multiplier := r.Values[mul_term.Multiplier]

			var product fr_bn254.Element
			product.Mul(&multiplicand, &multiplier)

			productVariable := r1cs.AddInternalVariable()

			terms = append(terms, r1cs.MakeTerm(&coefficient, productVariable))
		}

		for _, add_term := range gate.AddTerms {
			coefficient := r1cs.FromInterface(add_term.Coefficient)
			sum := add_term.Sum

			terms = append(terms, r1cs.MakeTerm(&coefficient, int(sum)))
		}

		r1c := constraint.R1C{
			L: constraint.LinearExpression{r1cs.MakeTerm(&COEFFICIENT_ONE, ONE)},
			R: terms,
			O: constraint.LinearExpression{},
		}

		r1cs.AddConstraint(r1c)
	}

	return r1cs, publicVariables, privateVariables
}

func buildWitnesses(r1cs *cs_bn254.R1CS, publicVariables fr_bn254.Vector, privateVariables fr_bn254.Vector) witness.Witness {
	fmt.Println("Public Variables", publicVariables.String())
	fmt.Println("Private Variables", privateVariables.String())

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

	// -1 because the first variable is the constant 1.
	realNbPublicVariables := r1cs.GetNbPublicVariables() - 1
	witness.Fill(realNbPublicVariables, r1cs.GetNbSecretVariables(), witnessValues)

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

	r1cs, publicVariables, privateVariables := buildR1CS(r)

	witness := buildWitnesses(r1cs, publicVariables, privateVariables)

	// Setup.
	provingKey, _, err := groth16.Setup(r1cs)
	if err != nil {
		log.Fatal(err)
	}

	// Prove.
	proof, err := groth16.Prove(r1cs, provingKey, witness)
	if err != nil {
		log.Fatal(err)
	}

	// Serialize proof
	var serialized_proof bytes.Buffer
	proof.WriteTo(&serialized_proof)
	proof_string := hex.EncodeToString(serialized_proof.Bytes())

	return C.CString(proof_string)
}

//export ProveWithPK
func ProveWithPK(rawR1CS string, encodedProvingKey string) *C.char {
	// Deserialize rawR1CS.
	var r structs.RawR1CS
	err := json.Unmarshal([]byte(rawR1CS), &r)
	if err != nil {
		log.Fatal(err)
	}

	r1cs, publicVariables, privateVariables := buildR1CS(r)

	witness := buildWitnesses(r1cs, publicVariables, privateVariables)

	// Deserialize proving key.
	provingKey := groth16.NewProvingKey(r1cs.CurveID())
	decodedProvingKey, err := hex.DecodeString(encodedProvingKey)
	if err != nil {
		log.Fatal(err)
	}
	_, err = provingKey.ReadFrom(bytes.NewReader([]byte(decodedProvingKey)))
	if err != nil {
		log.Fatal(err)
	}

	// Prove.
	proof, err := groth16.Prove(r1cs, provingKey, witness)
	if err != nil {
		log.Fatal(err)
	}

	// Serialize proof
	var serialized_proof bytes.Buffer
	proof.WriteTo(&serialized_proof)
	proof_string := hex.EncodeToString(serialized_proof.Bytes())

	return C.CString(proof_string)
}

//export VerifyWithMeta
func VerifyWithMeta(rawR1CS string, encodedProof string) bool {
	// Deserialize rawR1CS.
	var r structs.RawR1CS
	err := json.Unmarshal([]byte(rawR1CS), &r)
	if err != nil {
		log.Fatal(err)
	}

	r1cs, publicVariables, privateVariables := buildR1CS(r)

	witness := buildWitnesses(r1cs, publicVariables, privateVariables)

	// Deserialize proof.
	proof := groth16.NewProof(r1cs.CurveID())
	decodedProof, err := hex.DecodeString(encodedProof)
	if err != nil {
		log.Fatal(err)
	}
	_, err = proof.ReadFrom(bytes.NewReader([]byte(decodedProof)))
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
	if groth16.Verify(proof, vk, publicInputs) != nil {
		return false
	}

	return true
}

//export VerifyWithVK
func VerifyWithVK(rawR1CS string, encodedProof string, encodedVerifyingKey string) bool {
	// Deserialize rawR1CS.
	var r structs.RawR1CS
	err := json.Unmarshal([]byte(rawR1CS), &r)
	if err != nil {
		log.Fatal(err)
	}

	r1cs, publicVariables, privateVariables := buildR1CS(r)

	witness := buildWitnesses(r1cs, publicVariables, privateVariables)

	// Deserialize proof.
	proof := groth16.NewProof(r1cs.CurveID())
	decodedProof, err := hex.DecodeString(encodedProof)
	if err != nil {
		log.Fatal(err)
	}
	_, err = proof.ReadFrom(bytes.NewReader([]byte(decodedProof)))
	if err != nil {
		log.Fatal(err)
	}

	// Deserialize verifying key.
	verifyingKey := groth16.NewVerifyingKey(r1cs.CurveID())
	decodedVerifyingKey, err := hex.DecodeString(encodedVerifyingKey)
	if err != nil {
		log.Fatal(err)
	}
	_, err = verifyingKey.ReadFrom(bytes.NewReader(decodedVerifyingKey))
	if err != nil {
		log.Fatal(err)
	}

	// Retrieve public inputs.
	publicInputs, err := witness.Public()
	if err != nil {
		log.Fatal(err)
	}

	// Verify.
	if groth16.Verify(proof, verifyingKey, publicInputs) != nil {
		return false
	}

	return true
}

//export Preprocess
func Preprocess(rawR1CS string) (*C.char, *C.char) {
	// Deserialize rawR1CS.
	var r structs.RawR1CS
	err := json.Unmarshal([]byte(rawR1CS), &r)
	if err != nil {
		log.Fatal(err)
	}

	r1cs, _, _ := buildR1CS(r)

	// Setup.
	pk, vk, err := groth16.Setup(r1cs)
	if err != nil {
		log.Fatal(err)
	}

	// Serialize proving key.
	var serialized_pk bytes.Buffer
	pk.WriteTo(&serialized_pk)
	pk_string := hex.EncodeToString(serialized_pk.Bytes())

	// Serialize verifying key.
	var serialized_vk bytes.Buffer
	vk.WriteTo(&serialized_vk)
	vk_string := hex.EncodeToString(serialized_vk.Bytes())

	return C.CString(pk_string), C.CString(vk_string)
}

//export IntegrationTestFeltSerialization
func IntegrationTestFeltSerialization(encodedFelt string) *C.char {
	deserializedFelt := structs.DeserializeFelt(encodedFelt)
	fmt.Printf("| GO |n%vn", deserializedFelt)

	// Serialize the felt.
	serializedFelt := deserializedFelt.Bytes()

	// Encode the serialized felt.
	serializedFeltString := hex.EncodeToString(serializedFelt[:])

	return C.CString(serializedFeltString)
}

//export IntegrationTestFeltsSerialization
func IntegrationTestFeltsSerialization(encodedFelts string) *C.char {
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

//export IntegrationTestU64Serialization
func IntegrationTestU64Serialization(number uint64) uint64 {
	fmt.Println(number)
	return number
}

//export IntegrationTestMulTermSerialization
func IntegrationTestMulTermSerialization(mulTermJSON string) *C.char {
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

//export IntegrationTestMulTermsSerialization
func IntegrationTestMulTermsSerialization(mulTermsJSON string) *C.char {
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

//export IntegrationTestAddTermSerialization
func IntegrationTestAddTermSerialization(addTermJSON string) *C.char {
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

//export IntegrationTestAddTermsSerialization
func IntegrationTestAddTermsSerialization(addTermsJSON string) *C.char {
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

//export IntegrationTestRawGateSerialization
func IntegrationTestRawGateSerialization(rawGateJSON string) *C.char {
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

//export IntegrationTestRawGatesSerialization
func IntegrationTestRawGatesSerialization(rawGatesJSON string) *C.char {
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

//export IntegrationTestRawR1CSSerialization
func IntegrationTestRawR1CSSerialization(rawR1CSJSON string) *C.char {
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

func ExampleR1CS() {
	// build a constraint system; this is (usually) done by the frontend package
	// for this Example we want to manipulate the constraints and output a string representation
	// and build the linear expressions "manually".
	r1cs := cs_bn254.NewR1CS(0)

	ONE := r1cs.AddPublicVariable("1") // the "ONE" wire
	Y := r1cs.AddPublicVariable("Y")
	X := r1cs.AddSecretVariable("X")

	v0 := r1cs.AddInternalVariable() // X²
	v1 := r1cs.AddInternalVariable() // X³

	// coefficients
	cOne := r1cs.FromInterface(1)
	cFive := r1cs.FromInterface(5)

	// X² == X * X
	r1cs.AddConstraint(constraint.R1C{
		L: constraint.LinearExpression{r1cs.MakeTerm(&cOne, X)},
		R: constraint.LinearExpression{r1cs.MakeTerm(&cOne, X)},
		O: constraint.LinearExpression{r1cs.MakeTerm(&cOne, v0)},
	})

	// X³ == X² * X
	r1cs.AddConstraint(constraint.R1C{
		L: constraint.LinearExpression{r1cs.MakeTerm(&cOne, v0)},
		R: constraint.LinearExpression{r1cs.MakeTerm(&cOne, X)},
		O: constraint.LinearExpression{r1cs.MakeTerm(&cOne, v1)},
	})

	// Y == X³ + X + 5
	r1cs.AddConstraint(constraint.R1C{
		R: constraint.LinearExpression{r1cs.MakeTerm(&cOne, ONE)},
		L: constraint.LinearExpression{r1cs.MakeTerm(&cOne, Y)},
		O: constraint.LinearExpression{
			r1cs.MakeTerm(&cFive, ONE),
			r1cs.MakeTerm(&cOne, X),
			r1cs.MakeTerm(&cOne, v1),
		},
	})

	fmt.Println("Number of constraints", r1cs.GetNbConstraints())
	fmt.Println("Number of coefficients", r1cs.GetNbCoefficients())
	fmt.Println("Number of internal variables", r1cs.GetNbInternalVariables())
	fmt.Println("Number of public variables", r1cs.GetNbPublicVariables())
	fmt.Println("Number of secret variables", r1cs.GetNbSecretVariables())
	fmt.Println("Coefficients", r1cs.Coefficients)

	// get the constraints
	constraints, r := r1cs.GetConstraints()

	for _, r1c := range constraints {
		fmt.Println(r1c.String(r))
		// for more granularity use constraint.NewStringBuilder(r) that embeds a string.Builder
		// and has WriteLinearExpression and WriteTerm methods.
	}

	// Output:
	// X ⋅ X == v0
	// v0 ⋅ X == v1
	// Y ⋅ 1 == 5 + X + v1
}

func main() {
	// ExampleR1CS()

	// constrain x == y
	// constrain 0 == 0
	// rawR1CS := `{"gates":[{"add_terms":[{"coefficient":"0000000000000000000000000000000000000000000000000000000000000001","sum":1},{"coefficient":"30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000000","sum":2},{"coefficient":"30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000000","sum":3}],"constant_term":"0000000000000000000000000000000000000000000000000000000000000000","mul_terms":[]},{"add_terms":[{"coefficient":"30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000000","sum":5}],"constant_term":"0000000000000000000000000000000000000000000000000000000000000000","mul_terms":[{"coefficient":"0000000000000000000000000000000000000000000000000000000000000001","multiplicand":3,"multiplier":4}]},{"add_terms":[{"coefficient":"30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000000","sum":3}],"constant_term":"0000000000000000000000000000000000000000000000000000000000000000","mul_terms":[{"coefficient":"0000000000000000000000000000000000000000000000000000000000000001","multiplicand":3,"multiplier":5}]},{"add_terms":[{"coefficient":"0000000000000000000000000000000000000000000000000000000000000001","sum":5}],"constant_term":"0000000000000000000000000000000000000000000000000000000000000000","mul_terms":[]}],"num_constraints":11,"num_variables":7,"public_inputs":[2],"values":"00000006000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"}`
	// constrain 1 == 1
	// rawR1CS := `{"gates":[{"add_terms":[{"coefficient":"0000000000000000000000000000000000000000000000000000000000000001","sum":1},{"coefficient":"30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000000","sum":2},{"coefficient":"30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000000","sum":3}],"constant_term":"0000000000000000000000000000000000000000000000000000000000000000","mul_terms":[]},{"add_terms":[{"coefficient":"30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000000","sum":5}],"constant_term":"0000000000000000000000000000000000000000000000000000000000000000","mul_terms":[{"coefficient":"0000000000000000000000000000000000000000000000000000000000000001","multiplicand":3,"multiplier":4}]},{"add_terms":[{"coefficient":"30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000000","sum":3}],"constant_term":"0000000000000000000000000000000000000000000000000000000000000000","mul_terms":[{"coefficient":"0000000000000000000000000000000000000000000000000000000000000001","multiplicand":3,"multiplier":5}]},{"add_terms":[{"coefficient":"0000000000000000000000000000000000000000000000000000000000000001","sum":5}],"constant_term":"0000000000000000000000000000000000000000000000000000000000000000","mul_terms":[]}],"num_constraints":11,"num_variables":7,"public_inputs":[2],"values":"00000006000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"}`
	// constrain 2 == 2
	// rawR1CS := `{"gates":[{"add_terms":[{"coefficient":"0000000000000000000000000000000000000000000000000000000000000001","sum":1},{"coefficient":"30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000000","sum":2},{"coefficient":"30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000000","sum":3}],"constant_term":"0000000000000000000000000000000000000000000000000000000000000000","mul_terms":[]},{"add_terms":[{"coefficient":"30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000000","sum":5}],"constant_term":"0000000000000000000000000000000000000000000000000000000000000000","mul_terms":[{"coefficient":"0000000000000000000000000000000000000000000000000000000000000001","multiplicand":3,"multiplier":4}]},{"add_terms":[{"coefficient":"30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000000","sum":3}],"constant_term":"0000000000000000000000000000000000000000000000000000000000000000","mul_terms":[{"coefficient":"0000000000000000000000000000000000000000000000000000000000000001","multiplicand":3,"multiplier":5}]},{"add_terms":[{"coefficient":"0000000000000000000000000000000000000000000000000000000000000001","sum":5}],"constant_term":"0000000000000000000000000000000000000000000000000000000000000000","mul_terms":[]}],"num_constraints":11,"num_variables":7,"public_inputs":[2],"values":"00000006000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"}`
	// constrain 3 == 3
	rawR1CS := `{"gates":[{"add_terms":[{"coefficient":"0000000000000000000000000000000000000000000000000000000000000001","sum":1},{"coefficient":"30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000000","sum":2},{"coefficient":"30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000000","sum":3}],"constant_term":"0000000000000000000000000000000000000000000000000000000000000000","mul_terms":[]},{"add_terms":[{"coefficient":"30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000000","sum":5}],"constant_term":"0000000000000000000000000000000000000000000000000000000000000000","mul_terms":[{"coefficient":"0000000000000000000000000000000000000000000000000000000000000001","multiplicand":3,"multiplier":4}]},{"add_terms":[{"coefficient":"30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000000","sum":3}],"constant_term":"0000000000000000000000000000000000000000000000000000000000000000","mul_terms":[{"coefficient":"0000000000000000000000000000000000000000000000000000000000000001","multiplicand":3,"multiplier":5}]},{"add_terms":[{"coefficient":"0000000000000000000000000000000000000000000000000000000000000001","sum":5}],"constant_term":"0000000000000000000000000000000000000000000000000000000000000000","mul_terms":[]}],"num_constraints":11,"num_variables":7,"public_inputs":[2],"values":"00000006000000000000000000000000000000000000000000000000000000000000000300000000000000000000000000000000000000000000000000000000000000030000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"}`
	// Invalid
	invalidRawR1CS := `{"gates":[{"add_terms":[{"coefficient":"0000000000000000000000000000000000000000000000000000000000000001","sum":1},{"coefficient":"30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000000","sum":2},{"coefficient":"30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000000","sum":3}],"constant_term":"0000000000000000000000000000000000000000000000000000000000000000","mul_terms":[]},{"add_terms":[{"coefficient":"30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000000","sum":5}],"constant_term":"0000000000000000000000000000000000000000000000000000000000000000","mul_terms":[{"coefficient":"0000000000000000000000000000000000000000000000000000000000000001","multiplicand":3,"multiplier":4}]},{"add_terms":[{"coefficient":"30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000000","sum":3}],"constant_term":"0000000000000000000000000000000000000000000000000000000000000000","mul_terms":[{"coefficient":"0000000000000000000000000000000000000000000000000000000000000001","multiplicand":3,"multiplier":5}]},{"add_terms":[{"coefficient":"0000000000000000000000000000000000000000000000000000000000000001","sum":5}],"constant_term":"0000000000000000000000000000000000000000000000000000000000000000","mul_terms":[]}],"num_constraints":11,"num_variables":7,"public_inputs":[2],"values":"00000006000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000030000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"}`

	var r structs.RawR1CS
	err := json.Unmarshal([]byte(rawR1CS), &r)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("Gates: ", len(r.Gates))
	mulTerms := 0
	addTerms := 0
	for g, gate := range r.Gates {
		fmt.Println("Gate", g)
		fmt.Println()

		fmt.Println("MulTerms:")
		mulTerms += len(gate.MulTerms)
		for _, mulTerm := range gate.MulTerms {
			fmt.Println("MulTerm:", mulTerm)
			var product fr_bn254.Element
			product.Mul(&r.Values[mulTerm.Multiplier], &r.Values[mulTerm.Multiplicand])
			fmt.Println("Multiplication", mulTerm.Coefficient.String(), "*", r.Values[mulTerm.Multiplier].String(), "*", r.Values[mulTerm.Multiplicand].String(), "=", product.String())
			fmt.Println("Product:", product.String())
		}
		fmt.Println()

		addTerms += len(gate.AddTerms)
		fmt.Println("AddTerms:")
		for _, addTerm := range gate.AddTerms {
			fmt.Println("AddTerm:", addTerm)
			fmt.Println("Addition", addTerm.Coefficient.String(), "*", r.Values[addTerm.Sum].String())
		}
		fmt.Println()

		fmt.Println("ConstantTerm:", gate.ConstantTerm)
		fmt.Println()

		fmt.Println()
	}
	fmt.Println("MulTerms: ", mulTerms)
	fmt.Println("AddTerms: ", mulTerms)

	r1cs, publicVariables, privateVariables := buildR1CS(r)

	constraints, res := r1cs.GetConstraints()
	for _, r1c := range constraints {
		fmt.Println(r1c.String(res))
	}
	fmt.Println()
	fmt.Println("NbValues: ", len(r.Values))
	for _, value := range r.Values {
		fmt.Println("Value: ", value.String())
	}
	fmt.Println("NbPublicInputs: ", len(r.PublicInputs), "PublicInputs: ", r.PublicInputs)

	witness := buildWitnesses(r1cs, publicVariables, privateVariables)
	publicWitnesses, _ := witness.Public()

	// Setup.
	pk, vk, err := groth16.Setup(r1cs)
	if err != nil {
		log.Fatal(err)
	}

	// Prove.
	proof, err := groth16.Prove(r1cs, pk, witness)
	if err != nil {
		log.Fatal(err)
	}

	// Verify.
	verified := groth16.Verify(proof, vk, publicWitnesses)

	fmt.Println("Verifies with valid public inputs: ", verified == nil)
	fmt.Println()

	// Invalid verification (same proof, wrong public value).
	err = json.Unmarshal([]byte(invalidRawR1CS), &r)
	if err != nil {
		log.Fatal(err)
	}

	invalidR1CS, publicVariables, privateVariables := buildR1CS(r)

	constraints, res = invalidR1CS.GetConstraints()
	for _, r1c := range constraints {
		fmt.Println(r1c.String(res))
	}

	invalidWitness := buildWitnesses(invalidR1CS, publicVariables, privateVariables)
	invalidPublicWitnesses, _ := invalidWitness.Public()
	invalidVerified := groth16.Verify(proof, vk, invalidPublicWitnesses)

	fmt.Println("Valid Public Witnesses: ", publicWitnesses.Vector().(fr_bn254.Vector).String())
	fmt.Println("Invalid Public Witnesses: ", invalidPublicWitnesses.Vector().(fr_bn254.Vector).String())
	fmt.Println()

	fmt.Println("Verifies with invalid public inputs: ", invalidVerified == nil)
}
