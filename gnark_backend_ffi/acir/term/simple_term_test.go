package term

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"testing"

	backend_helpers "gnark_backend_ffi/internal/backend"

	"github.com/stretchr/testify/assert"
)

func TestAddTermUnmarshalJSON(t *testing.T) {
	encodedCoefficient, nonEncodedCoefficient := backend_helpers.RandomEncodedFelt()
	sum := rand.Uint32()
	addTerm := fmt.Sprintf(`{"coefficient":"%s","sum":%d}`, encodedCoefficient, sum)

	var a SimpleTerm
	err := json.Unmarshal([]byte(addTerm), &a)

	assert.NoError(t, err)
	assert.Equal(t, nonEncodedCoefficient, a.Coefficient)
	assert.Equal(t, sum, a.VariableIndex)
}

func TestAddTermsUnmarshalJSON(t *testing.T) {
	encodedCoefficient, nonEncodedCoefficient := backend_helpers.RandomEncodedFelt()
	sum := rand.Uint32()
	addTerms := fmt.Sprintf(`[{"coefficient":"%s","sum":%d},{"coefficient":"%s","sum":%d}]`, encodedCoefficient, sum, encodedCoefficient, sum)

	var a []SimpleTerm
	err := json.Unmarshal([]byte(addTerms), &a)

	assert.NoError(t, err)
	for _, addTerm := range a {
		assert.Equal(t, nonEncodedCoefficient, addTerm.Coefficient)
		assert.Equal(t, sum, addTerm.VariableIndex)
	}
}

func TestAddTermUnmarshalJSONThrowsErrorWrongJSONFormatCoefficient(t *testing.T) {
	encodedCoefficient, _ := backend_helpers.RandomEncodedFelt()
	sum := rand.Uint32()
	addTerm := fmt.Sprintf(`{"coeff":"%s","sum":%d}`, encodedCoefficient, sum)

	var a SimpleTerm
	err := json.Unmarshal([]byte(addTerm), &a)
	assert.Error(t, err)
}

func TestAddTermUnmarshalJSONThrowsErrorWrongJSONFormatSum(t *testing.T) {
	encodedCoefficient, _ := backend_helpers.RandomEncodedFelt()
	sum := rand.Uint32()
	addTerm := fmt.Sprintf(`{"coefficient":"%s","sm":%d}`, encodedCoefficient, sum)

	var a SimpleTerm
	err := json.Unmarshal([]byte(addTerm), &a)
	assert.Error(t, err)
}

func TestAddTermUnmarshalJSONThrowsErrorOddCoefficientLength(t *testing.T) {
	t.Skip("DeserializeFelt exits when error")
	sum := rand.Uint32()
	addTerm := fmt.Sprintf(`{"coefficient":"%s","sum":%d}`, "123", sum)

	var a SimpleTerm
	err := json.Unmarshal([]byte(addTerm), &a)
	assert.Error(t, err)
}
