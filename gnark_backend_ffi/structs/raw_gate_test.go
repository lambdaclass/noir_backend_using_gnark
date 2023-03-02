package structs

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TODO: Test error cases.

func TestRawGateTermUnmarshalJSON(t *testing.T) {
	mulTerms := randomMulTerms()
	addTerms := randomAddTerms()
	encodedConstantTerm, nonEncodedConstantTerm := SampleEncodedFelt()
	rawGate := fmt.Sprintf(`{"mul_terms":%s,"add_terms":%s,"constant_term":"%s"}`, mulTerms, addTerms, encodedConstantTerm)

	var r RawGate
	err := json.Unmarshal([]byte(rawGate), &r)

	assert.NoError(t, err)
	assert.Equal(t, UncheckedDeserializeMulTerms(mulTerms), r.MulTerms)
	assert.Equal(t, UncheckedDeserializeAddTerms(addTerms), r.AddTerms)
	assert.Equal(t, nonEncodedConstantTerm, r.ConstantTerm)
}

func TestRawGateTermsUnmarshalJSON(t *testing.T) {
	mulTerms := randomMulTerms()
	addTerms := randomAddTerms()
	encodedConstantTerm, nonEncodedConstantTerm := SampleEncodedFelt()
	rawGate := fmt.Sprintf(`{"mul_terms":%s,"add_terms":%s,"constant_term":"%s"}`, mulTerms, addTerms, encodedConstantTerm)
	rawGates := fmt.Sprintf(`[%s,%s]`, rawGate, rawGate)

	var r []RawGate
	err := json.Unmarshal([]byte(rawGates), &r)

	assert.NoError(t, err)
	for _, rawGate := range r {
		assert.Equal(t, UncheckedDeserializeMulTerms(mulTerms), rawGate.MulTerms)
		assert.Equal(t, UncheckedDeserializeAddTerms(addTerms), rawGate.AddTerms)
		assert.Equal(t, nonEncodedConstantTerm, rawGate.ConstantTerm)
	}
}

func TestRawGateTermUnmarshalJSONThrowsErrorWrongJSONFormatMulCoefficient(t *testing.T) {
	encodedCoefficient, _ := SampleEncodedFelt()
	multiplicand := rand.Uint32()
	multiplier := rand.Uint32()
	sum := rand.Uint32()
	mulTerms := fmt.Sprintf(`[{"cefficient":"%s","multiplicand":%d,"multiplier":%d},{"coefficient":"%s","multiplicand":%d,"multiplier":%d}]`, encodedCoefficient, multiplicand, multiplier, encodedCoefficient, multiplicand, multiplier)
	addTerms := fmt.Sprintf(`[{"coefficient":"%s","sum":%d},{"coefficient":"%s","sum":%d}]`, encodedCoefficient, sum, encodedCoefficient, sum)
	encodedConstantTerm, _ := SampleEncodedFelt()
	rawGate := fmt.Sprintf(`{"mul_terms":%s,"add_terms":%s,"constant_term":"%s"}`, mulTerms, addTerms, encodedConstantTerm)

	var r RawGate
	err := json.Unmarshal([]byte(rawGate), &r)
	assert.Error(t, err)
}

func TestRawGateTermUnmarshalJSONThrowsErrorWrongJSONFormatAddCoefficient(t *testing.T) {
	encodedCoefficient, _ := SampleEncodedFelt()
	multiplicand := rand.Uint32()
	multiplier := rand.Uint32()
	sum := rand.Uint32()
	mulTerms := fmt.Sprintf(`[{"coefficient":"%s","multiplicand":%d,"multiplier":%d},{"coefficient":"%s","multiplicand":%d,"multiplier":%d}]`, encodedCoefficient, multiplicand, multiplier, encodedCoefficient, multiplicand, multiplier)
	addTerms := fmt.Sprintf(`[{"coefficent":"%s","sum":%d},{"coefficient":"%s","sum":%d}]`, encodedCoefficient, sum, encodedCoefficient, sum)
	encodedConstantTerm, _ := SampleEncodedFelt()
	rawGate := fmt.Sprintf(`{"mul_terms":%s,"add_terms":%s,"constant_term":"%s"}`, mulTerms, addTerms, encodedConstantTerm)

	var r RawGate
	err := json.Unmarshal([]byte(rawGate), &r)
	assert.Error(t, err)
}

func TestRawGateTermUnmarshalJSONThrowsErrorWrongJSONFormatMulMultiplicand(t *testing.T) {
	encodedCoefficient, _ := SampleEncodedFelt()
	multiplicand := rand.Uint32()
	multiplier := rand.Uint32()
	sum := rand.Uint32()
	mulTerms := fmt.Sprintf(`[{"coefficient":"%s","multiplican":%d,"multiplier":%d},{"coefficient":"%s","multiplicand":%d,"multiplier":%d}]`, encodedCoefficient, multiplicand, multiplier, encodedCoefficient, multiplicand, multiplier)
	addTerms := fmt.Sprintf(`[{"coefficient":"%s","sum":%d},{"coefficient":"%s","sum":%d}]`, encodedCoefficient, sum, encodedCoefficient, sum)
	encodedConstantTerm, _ := SampleEncodedFelt()
	rawGate := fmt.Sprintf(`{"mul_terms":%s,"add_terms":%s,"constant_term":"%s"}`, mulTerms, addTerms, encodedConstantTerm)

	var r RawGate
	err := json.Unmarshal([]byte(rawGate), &r)
	assert.Error(t, err)
}

func TestRawGateTermUnmarshalJSONThrowsErrorWrongJSONFormatMulMultiplier(t *testing.T) {
	encodedCoefficient, _ := SampleEncodedFelt()
	multiplicand := rand.Uint32()
	multiplier := rand.Uint32()
	sum := rand.Uint32()
	mulTerms := fmt.Sprintf(`[{"coefficient":"%s","multiplicand":%d,"multiplie":%d},{"coefficient":"%s","multiplicand":%d,"multiplier":%d}]`, encodedCoefficient, multiplicand, multiplier, encodedCoefficient, multiplicand, multiplier)
	addTerms := fmt.Sprintf(`[{"coefficient":"%s","sum":%d},{"coefficient":"%s","sum":%d}]`, encodedCoefficient, sum, encodedCoefficient, sum)
	encodedConstantTerm, _ := SampleEncodedFelt()
	rawGate := fmt.Sprintf(`{"mul_terms":%s,"add_terms":%s,"constant_term":"%s"}`, mulTerms, addTerms, encodedConstantTerm)

	var r RawGate
	err := json.Unmarshal([]byte(rawGate), &r)
	assert.Error(t, err)
}

func TestRawGateTermUnmarshalJSONThrowsErrorWrongJSONFormatAddSum(t *testing.T) {
	encodedCoefficient, _ := SampleEncodedFelt()
	multiplicand := rand.Uint32()
	multiplier := rand.Uint32()
	sum := rand.Uint32()
	mulTerms := fmt.Sprintf(`[{"coefficient":"%s","multiplicand":%d,"multiplier":%d},{"coefficient":"%s","multiplicand":%d,"multiplier":%d}]`, encodedCoefficient, multiplicand, multiplier, encodedCoefficient, multiplicand, multiplier)
	addTerms := fmt.Sprintf(`[{"coefficient":"%s","um":%d},{"coefficient":"%s","sum":%d}]`, encodedCoefficient, sum, encodedCoefficient, sum)
	encodedConstantTerm, _ := SampleEncodedFelt()
	rawGate := fmt.Sprintf(`{"mul_terms":%s,"add_terms":%s,"constant_term":"%s"}`, mulTerms, addTerms, encodedConstantTerm)

	var r RawGate
	err := json.Unmarshal([]byte(rawGate), &r)
	assert.Error(t, err)
}

func TestRawGateTermUnmarshalJSONThrowsErrorWrongJSONFormatMulTerms(t *testing.T) {
	mulTerms := randomMulTerms()
	addTerms := randomAddTerms()
	encodedConstantTerm, _ := SampleEncodedFelt()
	rawGate := fmt.Sprintf(`{"mul_term":%s,"add_terms":%s,"constant_term":"%s"}`, mulTerms, addTerms, encodedConstantTerm)

	var r RawGate
	err := json.Unmarshal([]byte(rawGate), &r)
	assert.Error(t, err)
}

func TestRawGateTermUnmarshalJSONThrowsErrorWrongJSONFormatAddTerms(t *testing.T) {
	mulTerms := randomMulTerms()
	addTerms := randomAddTerms()
	encodedConstantTerm, _ := SampleEncodedFelt()
	rawGate := fmt.Sprintf(`{"mul_terms":%s,"add_term":%s,"constant_term":"%s"}`, mulTerms, addTerms, encodedConstantTerm)

	var r RawGate
	err := json.Unmarshal([]byte(rawGate), &r)
	assert.Error(t, err)
}

func TestRawGateTermUnmarshalJSONThrowsErrorWrongJSONFormatConstantTerm(t *testing.T) {
	mulTerms := randomMulTerms()
	addTerms := randomAddTerms()
	encodedConstantTerm, _ := SampleEncodedFelt()
	rawGate := fmt.Sprintf(`{"mul_terms":%s,"add_terms":%s,"constant_ter":"%s"}`, mulTerms, addTerms, encodedConstantTerm)

	var r RawGate
	err := json.Unmarshal([]byte(rawGate), &r)
	assert.Error(t, err)
}

func TestRawGateTermUnmarshalJSONThrowsErrorOddCoefficientLength(t *testing.T) {
	t.Skip("DeserializeFelt exits when error")
	encodedCoefficient := "123"
	multiplicand := rand.Uint32()
	multiplier := rand.Uint32()
	sum := rand.Uint32()
	mulTerms := fmt.Sprintf(`[{"coefficient":"%s","multiplicand":%d,"multiplier":%d},{"coefficient":"%s","multiplicand":%d,"multiplier":%d}]`, encodedCoefficient, multiplicand, multiplier, encodedCoefficient, multiplicand, multiplier)
	addTerms := fmt.Sprintf(`[{"coefficient":"%s","sum":%d},{"coefficient":"%s","sum":%d}]`, encodedCoefficient, sum, encodedCoefficient, sum)
	encodedConstantTerm, _ := SampleEncodedFelt()
	rawGate := fmt.Sprintf(`{"mul_terms":%s,"add_terms":%s,"constant_term":"%s"}`, mulTerms, addTerms, encodedConstantTerm)

	var r RawGate
	err := json.Unmarshal([]byte(rawGate), &r)
	assert.Error(t, err)
}

func TestRawGateTermUnmarshalJSONThrowsErrorOddConstantTerm(t *testing.T) {
	t.Skip("DeserializeFelt exits when error")
	mulTerms := randomMulTerms()
	addTerms := randomAddTerms()
	encodedConstantTerm := "123"
	rawGate := fmt.Sprintf(`{"mul_terms":%s,"add_terms":%s,"constant_term":"%s"}`, mulTerms, addTerms, encodedConstantTerm)

	var r RawGate
	err := json.Unmarshal([]byte(rawGate), &r)
	assert.Error(t, err)
}
