package structs

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TODO: Test error cases.

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

func TestAddTermUnmarshalJSONThrowsErrorWrongJSONFormat(t *testing.T) {
	sum := rand.Uint32()
	addTerm := fmt.Sprintf(`{"coeff":"%s","sum":%d}`, "1234", sum)

	var a AddTerm
	err := json.Unmarshal([]byte(addTerm), &a)
	assert.Error(t, err)
}
