package backend

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAddTermUnmarshalJSON(t *testing.T) {
	encodedCoefficient, nonEncodedCoefficient := SampleEncodedFelt()
	sum := rand.Uint32()
	addTerm := fmt.Sprintf(`{"coefficient":"%s","sum":%d}`, encodedCoefficient, sum)

	var a AddTerm
	err := json.Unmarshal([]byte(addTerm), &a)

	assert.NoError(t, err)
	assert.Equal(t, nonEncodedCoefficient, a.Coefficient)
	assert.Equal(t, sum, a.Sum)
}

func TestAddTermsUnmarshalJSON(t *testing.T) {
	encodedCoefficient, nonEncodedCoefficient := SampleEncodedFelt()
	sum := rand.Uint32()
	addTerms := fmt.Sprintf(`[{"coefficient":"%s","sum":%d},{"coefficient":"%s","sum":%d}]`, encodedCoefficient, sum, encodedCoefficient, sum)

	var a []AddTerm
	err := json.Unmarshal([]byte(addTerms), &a)

	assert.NoError(t, err)
	for _, addTerm := range a {
		assert.Equal(t, nonEncodedCoefficient, addTerm.Coefficient)
		assert.Equal(t, sum, addTerm.Sum)
	}
}

func TestAddTermUnmarshalJSONThrowsErrorWrongJSONFormatCoefficient(t *testing.T) {
	encodedCoefficient, _ := SampleEncodedFelt()
	sum := rand.Uint32()
	addTerm := fmt.Sprintf(`{"coeff":"%s","sum":%d}`, encodedCoefficient, sum)

	var a AddTerm
	err := json.Unmarshal([]byte(addTerm), &a)
	assert.Error(t, err)
}

func TestAddTermUnmarshalJSONThrowsErrorWrongJSONFormatSum(t *testing.T) {
	encodedCoefficient, _ := SampleEncodedFelt()
	sum := rand.Uint32()
	addTerm := fmt.Sprintf(`{"coefficient":"%s","sm":%d}`, encodedCoefficient, sum)

	var a AddTerm
	err := json.Unmarshal([]byte(addTerm), &a)
	assert.Error(t, err)
}

func TestAddTermUnmarshalJSONThrowsErrorOddCoefficientLength(t *testing.T) {
	t.Skip("DeserializeFelt exits when error")
	sum := rand.Uint32()
	addTerm := fmt.Sprintf(`{"coefficient":"%s","sum":%d}`, "123", sum)

	var a AddTerm
	err := json.Unmarshal([]byte(addTerm), &a)
	assert.Error(t, err)
}
