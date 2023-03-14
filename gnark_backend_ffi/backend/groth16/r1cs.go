package groth16

// import (
// 	"fmt"

// 	"github.com/consensys/gnark/constraint"
// )

// func buildR1CS(r groth16_backend.RawR1CS) (*cs_bn254.R1CS, fr_bn254.Vector, fr_bn254.Vector) {
// 	// Create R1CS.
// 	r1cs := cs_bn254.NewR1CS(int(r.NumConstraints))

// 	// Define the R1CS variables.
// 	_ = r1cs.AddPublicVariable("1") // ONE_WIRE
// 	var publicVariables fr_bn254.Vector
// 	var secretVariables fr_bn254.Vector
// 	for i, value := range r.Values {
// 		i++
// 		for _, publicInput := range r.PublicInputs {
// 			if uint32(i) == publicInput {
// 				r1cs.AddPublicVariable(fmt.Sprintf("public_%d", i))
// 				publicVariables = append(publicVariables, value)
// 			} else {
// 				r1cs.AddSecretVariable(fmt.Sprintf("secret_%d", i))
// 				secretVariables = append(secretVariables, value)
// 			}
// 		}
// 	}

// 	// Generate constraints.
// 	COEFFICIENT_ONE := r1cs.FromInterface(1)
// 	for _, gate := range r.Gates {
// 		var terms constraint.LinearExpression

// 		for _, mul_term := range gate.MulTerms {
// 			coefficient := r1cs.FromInterface(mul_term.Coefficient)
// 			multiplicand := r.Values[mul_term.MultiplicandIndex]
// 			multiplier := r.Values[mul_term.MultiplierIndex]
// 			var product fr_bn254.Element
// 			product.Mul(&multiplicand, &multiplier)

// 			productVariable := r1cs.AddInternalVariable()

// 			mulR1C := constraint.R1C{
// 				L: constraint.LinearExpression{r1cs.MakeTerm(&COEFFICIENT_ONE, int(mul_term.MultiplicandIndex))},
// 				R: constraint.LinearExpression{r1cs.MakeTerm(&COEFFICIENT_ONE, int(mul_term.MultiplierIndex))},
// 				O: constraint.LinearExpression{r1cs.MakeTerm(&coefficient, productVariable)},
// 			}

// 			r1cs.AddConstraint(mulR1C)

// 			terms = append(terms, r1cs.MakeTerm(&coefficient, productVariable))
// 		}

// 		for _, add_term := range gate.AddTerms {
// 			coefficient := r1cs.FromInterface(add_term.Coefficient)
// 			sum := add_term.VariableIndex

// 			terms = append(terms, r1cs.MakeTerm(&coefficient, int(sum)))
// 		}

// 		r1c := constraint.R1C{
// 			L: constraint.LinearExpression{r1cs.MakeTerm(&COEFFICIENT_ONE, 0)},
// 			R: terms,
// 			O: constraint.LinearExpression{},
// 		}

// 		r1cs.AddConstraint(r1c)
// 	}

// 	return r1cs, publicVariables, secretVariables
// }

// //export ProveWithMeta
// func ProveWithMeta(rawR1CS string) *C.char {
// 	// Deserialize rawR1CS.
// 	var r groth16_backend.RawR1CS
// 	err := json.Unmarshal([]byte(rawR1CS), &r)
// 	if err != nil {
// 		log.Fatal(err)
// 	}

// 	r1cs, publicVariables, privateVariables := buildR1CS(r)

// 	witness := buildWitnesses(r1cs.CurveID().ScalarField(), publicVariables, privateVariables, r1cs.GetNbPublicVariables()-1, r1cs.GetNbSecretVariables())

// 	// Setup.
// 	provingKey, _, err := groth16.Setup(r1cs)
// 	if err != nil {
// 		log.Fatal(err)
// 	}

// 	// Prove.
// 	proof, err := groth16.Prove(r1cs, provingKey, witness)
// 	if err != nil {
// 		log.Fatal(err)
// 	}

// 	// Serialize proof
// 	var serialized_proof bytes.Buffer
// 	proof.WriteTo(&serialized_proof)
// 	proof_string := hex.EncodeToString(serialized_proof.Bytes())

// 	return C.CString(proof_string)
// }

// //export ProveWithPK
// func ProveWithPK(rawR1CS string, encodedProvingKey string) *C.char {
// 	// Deserialize rawR1CS.
// 	var r groth16_backend.RawR1CS
// 	err := json.Unmarshal([]byte(rawR1CS), &r)
// 	if err != nil {
// 		log.Fatal(err)
// 	}

// 	r1cs, publicVariables, privateVariables := buildR1CS(r)

// 	witness := buildWitnesses(r1cs.CurveID().ScalarField(), publicVariables, privateVariables, r1cs.GetNbPublicVariables()-1, r1cs.GetNbSecretVariables())

// 	// Deserialize proving key.
// 	provingKey := groth16.NewProvingKey(r1cs.CurveID())
// 	decodedProvingKey, err := hex.DecodeString(encodedProvingKey)
// 	if err != nil {
// 		log.Fatal(err)
// 	}
// 	_, err = provingKey.ReadFrom(bytes.NewReader([]byte(decodedProvingKey)))
// 	if err != nil {
// 		log.Fatal(err)
// 	}

// 	// Prove.
// 	proof, err := groth16.Prove(r1cs, provingKey, witness)
// 	if err != nil {
// 		log.Fatal(err)
// 	}

// 	// Serialize proof
// 	var serialized_proof bytes.Buffer
// 	proof.WriteTo(&serialized_proof)
// 	proof_string := hex.EncodeToString(serialized_proof.Bytes())

// 	return C.CString(proof_string)
// }

// //export VerifyWithMeta
// func VerifyWithMeta(rawR1CS string, encodedProof string) bool {
// 	// Deserialize rawR1CS.
// 	var r groth16_backend.RawR1CS
// 	err := json.Unmarshal([]byte(rawR1CS), &r)
// 	if err != nil {
// 		log.Fatal(err)
// 	}

// 	r1cs, publicVariables, privateVariables := buildR1CS(r)

// 	witness := buildWitnesses(r1cs.CurveID().ScalarField(), publicVariables, privateVariables, r1cs.GetNbPublicVariables()-1, r1cs.GetNbSecretVariables())

// 	// Deserialize proof.
// 	proof := groth16.NewProof(r1cs.CurveID())
// 	decodedProof, err := hex.DecodeString(encodedProof)
// 	if err != nil {
// 		log.Fatal(err)
// 	}
// 	_, err = proof.ReadFrom(bytes.NewReader([]byte(decodedProof)))
// 	if err != nil {
// 		log.Fatal(err)
// 	}

// 	// Setup.
// 	_, vk, err := groth16.Setup(r1cs)
// 	if err != nil {
// 		log.Fatal(err)
// 	}

// 	// Retrieve public inputs.
// 	publicInputs, err := witness.Public()
// 	if err != nil {
// 		log.Fatal(err)
// 	}

// 	// Verify.
// 	if groth16.Verify(proof, vk, publicInputs) != nil {
// 		return false
// 	}

// 	return true
// }

// //export VerifyWithVK
// func VerifyWithVK(rawR1CS string, encodedProof string, encodedVerifyingKey string) bool {
// 	// Deserialize rawR1CS.
// 	var r groth16_backend.RawR1CS
// 	err := json.Unmarshal([]byte(rawR1CS), &r)
// 	if err != nil {
// 		log.Fatal(err)
// 	}

// 	r1cs, publicVariables, privateVariables := buildR1CS(r)

// 	witness := buildWitnesses(r1cs.CurveID().ScalarField(), publicVariables, privateVariables, r1cs.GetNbPublicVariables()-1, r1cs.GetNbSecretVariables())

// 	// Deserialize proof.
// 	proof := groth16.NewProof(r1cs.CurveID())
// 	decodedProof, err := hex.DecodeString(encodedProof)
// 	if err != nil {
// 		log.Fatal(err)
// 	}
// 	_, err = proof.ReadFrom(bytes.NewReader(decodedProof))
// 	if err != nil {
// 		log.Fatal(err)
// 	}

// 	// Deserialize verifying key.
// 	verifyingKey := groth16.NewVerifyingKey(r1cs.CurveID())
// 	decodedVerifyingKey, err := hex.DecodeString(encodedVerifyingKey)
// 	if err != nil {
// 		log.Fatal(err)
// 	}
// 	_, err = verifyingKey.ReadFrom(bytes.NewReader(decodedVerifyingKey))
// 	if err != nil {
// 		log.Fatal(err)
// 	}

// 	// Retrieve public inputs.
// 	publicInputs, err := witness.Public()
// 	if err != nil {
// 		log.Fatal(err)
// 	}

// 	// Verify.
// 	if groth16.Verify(proof, verifyingKey, publicInputs) != nil {
// 		return false
// 	}

// 	return true
// }

// //export Preprocess
// func Preprocess(rawR1CS string) (*C.char, *C.char) {
// 	// Deserialize rawR1CS.
// 	var r groth16_backend.RawR1CS
// 	err := json.Unmarshal([]byte(rawR1CS), &r)
// 	if err != nil {
// 		log.Fatal(err)
// 	}

// 	r1cs, _, _ := buildR1CS(r)

// 	// Setup.
// 	provingKey, verifyingKey, err := groth16.Setup(r1cs)
// 	if err != nil {
// 		log.Fatal(err)
// 	}

// 	// Serialize proving key.
// 	var serializedProvingKey bytes.Buffer
// 	provingKey.WriteTo(&serializedProvingKey)
// 	provingKeyString := hex.EncodeToString(serializedProvingKey.Bytes())

// 	// Serialize verifying key.
// 	var serializedVerifyingKey bytes.Buffer
// 	verifyingKey.WriteTo(&serializedVerifyingKey)
// 	verifyingKeyString := hex.EncodeToString(serializedVerifyingKey.Bytes())

// 	return C.CString(provingKeyString), C.CString(verifyingKeyString)
// }

// //export PlonkProveWithMeta
// func PlonkProveWithMeta(acirJSON string, encodedValues string) *C.char {
// 	return C.CString("Unimplemented")
// }

// //export IntegrationTestFeltSerialization
// func IntegrationTestFeltSerialization(encodedFelt string) *C.char {
// 	deserializedFelt := backend_helpers.DeserializeFelt(encodedFelt)
// 	fmt.Printf("| GO |n%vn", deserializedFelt)

// 	// Serialize the felt.
// 	serializedFelt := deserializedFelt.Bytes()

// 	// Encode the serialized felt.
// 	serializedFeltString := hex.EncodeToString(serializedFelt[:])

// 	return C.CString(serializedFeltString)
// }

// //export IntegrationTestFeltsSerialization
// func IntegrationTestFeltsSerialization(encodedFelts string) *C.char {
// 	deserializedFelts := backend_helpers.DeserializeFelts(encodedFelts)

// 	// Serialize the felt.
// 	serializedFelts, err := deserializedFelts.MarshalBinary()
// 	if err != nil {
// 		log.Fatal(err)
// 	}

// 	// Encode the serialized felt.
// 	serializedFeltsString := hex.EncodeToString(serializedFelts[:])

// 	return C.CString(serializedFeltsString)
// }

// //export IntegrationTestU64Serialization
// func IntegrationTestU64Serialization(number uint64) uint64 {
// 	fmt.Println(number)
// 	return number
// }

// //export IntegrationTestMulTermSerialization
// func IntegrationTestMulTermSerialization(mulTermJSON string) *C.char {
// 	var deserializedMulTerm term.MulTerm
// 	err := json.Unmarshal([]byte(mulTermJSON), &deserializedMulTerm)
// 	if err != nil {
// 		log.Fatal(err)
// 	}

// 	fmt.Println("| GO |")
// 	fmt.Println("", deserializedMulTerm.Coefficient)
// 	fmt.Println("", deserializedMulTerm.MultiplicandIndex)
// 	fmt.Println("", deserializedMulTerm.MultiplierIndex)

// 	serializedMulTerm, err := json.Marshal(deserializedMulTerm)
// 	if err != nil {
// 		log.Fatal(err)
// 	}

// 	return C.CString(string(serializedMulTerm))
// }

// //export IntegrationTestMulTermsSerialization
// func IntegrationTestMulTermsSerialization(mulTermsJSON string) *C.char {
// 	var deserializedMulTerms term.MulTerms
// 	err := json.Unmarshal([]byte(mulTermsJSON), &deserializedMulTerms)
// 	if err != nil {
// 		log.Fatal(err)
// 	}

// 	fmt.Println("| GO |")
// 	for _, deserializedMulTerm := range deserializedMulTerms {
// 		fmt.Println("", deserializedMulTerm.Coefficient)
// 		fmt.Println("", deserializedMulTerm.MultiplicandIndex)
// 		fmt.Println("", deserializedMulTerm.MultiplierIndex)
// 		fmt.Println()
// 	}

// 	serializedMulTerms, err := json.Marshal(deserializedMulTerms)
// 	if err != nil {
// 		log.Fatal(err)
// 	}

// 	return C.CString(string(serializedMulTerms))
// }

// //export IntegrationTestAddTermSerialization
// func IntegrationTestAddTermSerialization(addTermJSON string) *C.char {
// 	var deserializedAddTerm term.SimpleTerm
// 	err := json.Unmarshal([]byte(addTermJSON), &deserializedAddTerm)
// 	if err != nil {
// 		log.Fatal(err)
// 	}

// 	fmt.Println("| GO |")
// 	fmt.Println("", deserializedAddTerm.Coefficient)
// 	fmt.Println("", deserializedAddTerm.VariableIndex)

// 	serializedAddTerm, err := json.Marshal(deserializedAddTerm)
// 	if err != nil {
// 		log.Fatal(err)
// 	}

// 	return C.CString(string(serializedAddTerm))
// }

// //export IntegrationTestAddTermsSerialization
// func IntegrationTestAddTermsSerialization(addTermsJSON string) *C.char {
// 	var deserializedAddTerms term.SimpleTerms
// 	err := json.Unmarshal([]byte(addTermsJSON), &deserializedAddTerms)
// 	if err != nil {
// 		log.Fatal(err)
// 	}

// 	fmt.Println("| GO |")
// 	for _, deserializedAddTerm := range deserializedAddTerms {
// 		fmt.Println("", deserializedAddTerm.Coefficient)
// 		fmt.Println("", deserializedAddTerm.VariableIndex)
// 		fmt.Println()
// 	}

// 	serializedAddTerms, err := json.Marshal(deserializedAddTerms)
// 	if err != nil {
// 		log.Fatal(err)
// 	}

// 	return C.CString(string(serializedAddTerms))
// }

// //export IntegrationTestRawGateSerialization
// func IntegrationTestRawGateSerialization(rawGateJSON string) *C.char {
// 	var deserializedRawGate groth16_backend.RawGate
// 	err := json.Unmarshal([]byte(rawGateJSON), &deserializedRawGate)
// 	if err != nil {
// 		log.Fatal(err)
// 	}

// 	fmt.Println("| GO |")
// 	fmt.Println("", deserializedRawGate.MulTerms)
// 	fmt.Println("", deserializedRawGate.AddTerms)
// 	fmt.Println("", deserializedRawGate.ConstantTerm)
// 	fmt.Println()

// 	serializedRawGate, err := json.Marshal(deserializedRawGate)
// 	if err != nil {
// 		log.Fatal(err)
// 	}

// 	return C.CString(string(serializedRawGate))
// }

// //export IntegrationTestRawGatesSerialization
// func IntegrationTestRawGatesSerialization(rawGatesJSON string) *C.char {
// 	var deserializedRawGates []groth16_backend.RawGate
// 	err := json.Unmarshal([]byte(rawGatesJSON), &deserializedRawGates)
// 	if err != nil {
// 		log.Fatal(err)
// 	}

// 	fmt.Println("| GO |")
// 	for _, deserializedRawGate := range deserializedRawGates {
// 		fmt.Println("", deserializedRawGate.MulTerms)
// 		fmt.Println("", deserializedRawGate.AddTerms)
// 		fmt.Println("", deserializedRawGate.ConstantTerm)
// 		fmt.Println()
// 	}

// 	serializedRawGate, err := json.Marshal(deserializedRawGates)
// 	if err != nil {
// 		log.Fatal(err)
// 	}

// 	return C.CString(string(serializedRawGate))
// }

// //export IntegrationTestRawR1CSSerialization
// func IntegrationTestRawR1CSSerialization(rawR1CSJSON string) *C.char {
// 	var deserializedRawR1CS groth16_backend.RawR1CS
// 	err := json.Unmarshal([]byte(rawR1CSJSON), &deserializedRawR1CS)
// 	if err != nil {
// 		log.Fatal(err)
// 	}

// 	fmt.Println("| GO |")
// 	fmt.Println("Gates: ", deserializedRawR1CS.Gates)
// 	fmt.Println("Public inputs: ", deserializedRawR1CS.PublicInputs)
// 	fmt.Println("Values: ", deserializedRawR1CS.Values)
// 	fmt.Println("Number of variables: ", deserializedRawR1CS.NumVariables)
// 	fmt.Println("Number of constraints: ", deserializedRawR1CS.NumConstraints)
// 	fmt.Println()

// 	serializedRawR1CS, err := json.Marshal(deserializedRawR1CS)
// 	if err != nil {
// 		log.Fatal(err)
// 	}

// 	return C.CString(string(serializedRawR1CS))
// }
