package structs

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TODO: Test error cases.

func TestRawR1CSTermUnmarshalJSON(t *testing.T) {
	encodedCoefficient, _ := SampleEncodedFelt()
	multiplicand := rand.Uint32()
	multiplier := rand.Uint32()
	sum := rand.Uint32()
	mulTerms := fmt.Sprintf(`[{"coefficient":"%s","multiplicand":%d,"multiplier":%d},{"coefficient":"%s","multiplicand":%d,"multiplier":%d}]`, encodedCoefficient, multiplicand, multiplier, encodedCoefficient, multiplicand, multiplier)
	addTerms := fmt.Sprintf(`[{"coefficient":"%s","sum":%d},{"coefficient":"%s","sum":%d}]`, encodedCoefficient, sum, encodedCoefficient, sum)
	encodedConstantTerm, _ := SampleEncodedFelt()
	rawGate := fmt.Sprintf(`{"mul_terms":%s,"add_terms":%s,"constant_term":"%s"}`, mulTerms, addTerms, encodedConstantTerm)
	rawGates := fmt.Sprintf(`[%s,%s]`, rawGate, rawGate)
	publicInputs := fmt.Sprintf("[%d,%d,%d]", multiplicand, multiplier, sum)
	encodedValues, nonEncodedValues := SampleEncodedFelts()
	numVariables := uint64(10)
	numConstraints := uint64(10)
	rawR1CS := fmt.Sprintf(`{"gates":%s,"public_inputs":%s,"values":"%s","num_variables":%d,"num_constraints":%d}`, rawGates, publicInputs, encodedValues, numVariables, numConstraints)

	var r RawR1CS
	err := json.Unmarshal([]byte(rawR1CS), &r)

	assert.NoError(t, err)
	assert.Equal(t, UncheckedDeserializeRawGates(rawGates), r.Gates)
	assert.Equal(t, Witnesses{multiplicand, multiplier, sum}, r.PublicInputs)
	assert.Equal(t, nonEncodedValues, r.Values)
	assert.Equal(t, numConstraints, r.NumConstraints)
	assert.Equal(t, numVariables, r.NumVariables)
}

func TestRawR1CSTermUnmarshalJSONThrowsErrorWrongJSONFormatGates(t *testing.T) {
	encodedCoefficient, _ := SampleEncodedFelt()
	multiplicand := rand.Uint32()
	multiplier := rand.Uint32()
	sum := rand.Uint32()
	mulTerms := fmt.Sprintf(`[{"coefficient":"%s","multiplicand":%d,"multiplier":%d},{"coefficient":"%s","multiplicand":%d,"multiplier":%d}]`, encodedCoefficient, multiplicand, multiplier, encodedCoefficient, multiplicand, multiplier)
	addTerms := fmt.Sprintf(`[{"coefficient":"%s","sum":%d},{"coefficient":"%s","sum":%d}]`, encodedCoefficient, sum, encodedCoefficient, sum)
	encodedConstantTerm, _ := SampleEncodedFelt()
	rawGate := fmt.Sprintf(`{"mul_terms":%s,"add_terms":%s,"constant_term":"%s"}`, mulTerms, addTerms, encodedConstantTerm)
	rawGates := fmt.Sprintf(`[%s,%s]`, rawGate, rawGate)
	publicInputs := fmt.Sprintf("[%d,%d,%d]", multiplicand, multiplier, sum)
	encodedValues, _ := SampleEncodedFelts()
	numVariables := uint64(10)
	numConstraints := uint64(10)
	rawR1CS := fmt.Sprintf(`{"gate":%s,"public_inputs":%s,"values":"%s","num_variables":%d,"num_constraints":%d}`, rawGates, publicInputs, encodedValues, numVariables, numConstraints)

	var r RawR1CS
	err := json.Unmarshal([]byte(rawR1CS), &r)
	assert.Error(t, err)
}

func TestRawR1CSTermUnmarshalJSONThrowsErrorWrongJSONFormatPublicInputs(t *testing.T) {
	encodedCoefficient, _ := SampleEncodedFelt()
	multiplicand := rand.Uint32()
	multiplier := rand.Uint32()
	sum := rand.Uint32()
	mulTerms := fmt.Sprintf(`[{"coefficient":"%s","multiplicand":%d,"multiplier":%d},{"coefficient":"%s","multiplicand":%d,"multiplier":%d}]`, encodedCoefficient, multiplicand, multiplier, encodedCoefficient, multiplicand, multiplier)
	addTerms := fmt.Sprintf(`[{"coefficient":"%s","sum":%d},{"coefficient":"%s","sum":%d}]`, encodedCoefficient, sum, encodedCoefficient, sum)
	encodedConstantTerm, _ := SampleEncodedFelt()
	rawGate := fmt.Sprintf(`{"mul_terms":%s,"add_terms":%s,"constant_term":"%s"}`, mulTerms, addTerms, encodedConstantTerm)
	rawGates := fmt.Sprintf(`[%s,%s]`, rawGate, rawGate)
	publicInputs := fmt.Sprintf("[%d,%d,%d]", multiplicand, multiplier, sum)
	encodedValues, _ := SampleEncodedFelts()
	numVariables := uint64(10)
	numConstraints := uint64(10)
	rawR1CS := fmt.Sprintf(`{"gates":%s,"public_input":%s,"values":"%s","num_variables":%d,"num_constraints":%d}`, rawGates, publicInputs, encodedValues, numVariables, numConstraints)

	var r RawR1CS
	err := json.Unmarshal([]byte(rawR1CS), &r)
	assert.Error(t, err)
}

func TestRawR1CSTermUnmarshalJSONThrowsErrorWrongJSONFormatValues(t *testing.T) {
	encodedCoefficient, _ := SampleEncodedFelt()
	multiplicand := rand.Uint32()
	multiplier := rand.Uint32()
	sum := rand.Uint32()
	mulTerms := fmt.Sprintf(`[{"coefficient":"%s","multiplicand":%d,"multiplier":%d},{"coefficient":"%s","multiplicand":%d,"multiplier":%d}]`, encodedCoefficient, multiplicand, multiplier, encodedCoefficient, multiplicand, multiplier)
	addTerms := fmt.Sprintf(`[{"coefficient":"%s","sum":%d},{"coefficient":"%s","sum":%d}]`, encodedCoefficient, sum, encodedCoefficient, sum)
	encodedConstantTerm, _ := SampleEncodedFelt()
	rawGate := fmt.Sprintf(`{"mul_terms":%s,"add_terms":%s,"constant_term":"%s"}`, mulTerms, addTerms, encodedConstantTerm)
	rawGates := fmt.Sprintf(`[%s,%s]`, rawGate, rawGate)
	publicInputs := fmt.Sprintf("[%d,%d,%d]", multiplicand, multiplier, sum)
	encodedValues, _ := SampleEncodedFelts()
	numVariables := uint64(10)
	numConstraints := uint64(10)
	rawR1CS := fmt.Sprintf(`{"gates":%s,"public_inputs":%s,"valus":"%s","num_variables":%d,"num_constraints":%d}`, rawGates, publicInputs, encodedValues, numVariables, numConstraints)

	var r RawR1CS
	err := json.Unmarshal([]byte(rawR1CS), &r)
	assert.Error(t, err)
}

func TestRawR1CSTermUnmarshalJSONThrowsErrorWrongJSONFormatNumVariables(t *testing.T) {
	encodedCoefficient, _ := SampleEncodedFelt()
	multiplicand := rand.Uint32()
	multiplier := rand.Uint32()
	sum := rand.Uint32()
	mulTerms := fmt.Sprintf(`[{"coefficient":"%s","multiplicand":%d,"multiplier":%d},{"coefficient":"%s","multiplicand":%d,"multiplier":%d}]`, encodedCoefficient, multiplicand, multiplier, encodedCoefficient, multiplicand, multiplier)
	addTerms := fmt.Sprintf(`[{"coefficient":"%s","sum":%d},{"coefficient":"%s","sum":%d}]`, encodedCoefficient, sum, encodedCoefficient, sum)
	encodedConstantTerm, _ := SampleEncodedFelt()
	rawGate := fmt.Sprintf(`{"mul_terms":%s,"add_terms":%s,"constant_term":"%s"}`, mulTerms, addTerms, encodedConstantTerm)
	rawGates := fmt.Sprintf(`[%s,%s]`, rawGate, rawGate)
	publicInputs := fmt.Sprintf("[%d,%d,%d]", multiplicand, multiplier, sum)
	encodedValues, _ := SampleEncodedFelts()
	numVariables := uint64(10)
	numConstraints := uint64(10)
	rawR1CS := fmt.Sprintf(`{"gates":%s,"public_inputs":%s,"values":"%s","nm_variables":%d,"num_constraints":%d}`, rawGates, publicInputs, encodedValues, numVariables, numConstraints)

	var r RawR1CS
	err := json.Unmarshal([]byte(rawR1CS), &r)
	assert.Error(t, err)
}

func TestRawR1CSTermUnmarshalJSONThrowsErrorWrongJSONFormatNumConstraints(t *testing.T) {
	encodedCoefficient, _ := SampleEncodedFelt()
	multiplicand := rand.Uint32()
	multiplier := rand.Uint32()
	sum := rand.Uint32()
	mulTerms := fmt.Sprintf(`[{"coefficient":"%s","multiplicand":%d,"multiplier":%d},{"coefficient":"%s","multiplicand":%d,"multiplier":%d}]`, encodedCoefficient, multiplicand, multiplier, encodedCoefficient, multiplicand, multiplier)
	addTerms := fmt.Sprintf(`[{"coefficient":"%s","sum":%d},{"coefficient":"%s","sum":%d}]`, encodedCoefficient, sum, encodedCoefficient, sum)
	encodedConstantTerm, _ := SampleEncodedFelt()
	rawGate := fmt.Sprintf(`{"mul_terms":%s,"add_terms":%s,"constant_term":"%s"}`, mulTerms, addTerms, encodedConstantTerm)
	rawGates := fmt.Sprintf(`[%s,%s]`, rawGate, rawGate)
	publicInputs := fmt.Sprintf("[%d,%d,%d]", multiplicand, multiplier, sum)
	encodedValues, _ := SampleEncodedFelts()
	numVariables := uint64(10)
	numConstraints := uint64(10)
	rawR1CS := fmt.Sprintf(`{"gates":%s,"public_inputs":%s,"values":"%s","num_variables":%d,"um_constraints":%d}`, rawGates, publicInputs, encodedValues, numVariables, numConstraints)

	var r RawR1CS
	err := json.Unmarshal([]byte(rawR1CS), &r)
	assert.Error(t, err)
}

func TestRawR1CSTermUnmarshalJSONThrowsErrorOddLengthValues(t *testing.T) {
	t.Skip("DeserializeFelt exits when error")
	encodedCoefficient, _ := SampleEncodedFelt()
	multiplicand := rand.Uint32()
	multiplier := rand.Uint32()
	sum := rand.Uint32()
	mulTerms := fmt.Sprintf(`[{"coefficient":"%s","multiplicand":%d,"multiplier":%d},{"coefficient":"%s","multiplicand":%d,"multiplier":%d}]`, encodedCoefficient, multiplicand, multiplier, encodedCoefficient, multiplicand, multiplier)
	addTerms := fmt.Sprintf(`[{"coefficient":"%s","sum":%d},{"coefficient":"%s","sum":%d}]`, encodedCoefficient, sum, encodedCoefficient, sum)
	encodedConstantTerm, _ := SampleEncodedFelt()
	rawGate := fmt.Sprintf(`{"mul_terms":%s,"add_terms":%s,"constant_term":"%s"}`, mulTerms, addTerms, encodedConstantTerm)
	rawGates := fmt.Sprintf(`[%s,%s]`, rawGate, rawGate)
	publicInputs := fmt.Sprintf("[%d,%d,%d]", multiplicand, multiplier, sum)
	encodedValues := "123"
	numVariables := uint64(10)
	numConstraints := uint64(10)
	rawR1CS := fmt.Sprintf(`{"gates":%s,"public_inputs":%s,"values":"%s","num_variables":%d,"num_constraints":%d}`, rawGates, publicInputs, encodedValues, numVariables, numConstraints)

	var r RawR1CS
	err := json.Unmarshal([]byte(rawR1CS), &r)
	assert.Error(t, err)
}
