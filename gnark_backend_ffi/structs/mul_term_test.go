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
	encodedCoefficient, _ := SampleEncodedFelt()
	multiplicand := rand.Uint32()
	multiplier := rand.Uint32()
	mulTerm := fmt.Sprintf(`{"coefficient":"%s","multiplicand":%d,"multiplier":%d}`, encodedCoefficient, multiplicand, multiplier)

	var m MulTerm
	err := json.Unmarshal([]byte(mulTerm), &m)
	if err != nil {
		log.Fatal(err)
	}

	assert.NoError(t, err)
}

func TestMulTermsUnmarshalJSON(t *testing.T) {
	encodedCoefficient, _ := SampleEncodedFelt()
	multiplicand := rand.Uint32()
	multiplier := rand.Uint32()
	mulTerms := fmt.Sprintf(`[{"coefficient":"%s","multiplicand":%d,"multiplier":%d},{"coefficient":"%s","multiplicand":%d,"multiplier":%d}]`, encodedCoefficient, multiplicand, multiplier, encodedCoefficient, multiplicand, multiplier)

	var m []MulTerm
	err := json.Unmarshal([]byte(mulTerms), &m)
	if err != nil {
		log.Fatal(err)
	}

	assert.NoError(t, err)
}
