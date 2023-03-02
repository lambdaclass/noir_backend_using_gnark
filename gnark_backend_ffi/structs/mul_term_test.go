package structs

import (
	"encoding/json"
	"fmt"
	"log"
	"math/rand"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TODO: Test error cases.

func TestMulTermUnmarshalJSON(t *testing.T) {
	encodedCoefficient, nonEncodedCoefficient := SampleEncodedFelt()
	multiplicand := rand.Uint32()
	multiplier := rand.Uint32()
	mulTerm := fmt.Sprintf(`{"coefficient":"%s","multiplicand":%d,"multiplier":%d}`, encodedCoefficient, multiplicand, multiplier)

	var m MulTerm
	err := json.Unmarshal([]byte(mulTerm), &m)
	if err != nil {
		log.Fatal(err)
	}

	assert.NoError(t, err)
	assert.Equal(t, nonEncodedCoefficient, m.Coefficient)
	assert.Equal(t, multiplicand, m.Multiplicand)
	assert.Equal(t, multiplier, m.Multiplier)
}

func TestMulTermsUnmarshalJSON(t *testing.T) {
	encodedCoefficient, nonEncodedCoefficient := SampleEncodedFelt()
	multiplicand := rand.Uint32()
	multiplier := rand.Uint32()
	mulTerms := fmt.Sprintf(`[{"coefficient":"%s","multiplicand":%d,"multiplier":%d},{"coefficient":"%s","multiplicand":%d,"multiplier":%d}]`, encodedCoefficient, multiplicand, multiplier, encodedCoefficient, multiplicand, multiplier)

	var m []MulTerm
	err := json.Unmarshal([]byte(mulTerms), &m)
	if err != nil {
		log.Fatal(err)
	}

	assert.NoError(t, err)
	for _, mulTerm := range m {
		assert.Equal(t, nonEncodedCoefficient, mulTerm.Coefficient)
		assert.Equal(t, multiplicand, mulTerm.Multiplicand)
		assert.Equal(t, multiplier, mulTerm.Multiplier)
	}
}
