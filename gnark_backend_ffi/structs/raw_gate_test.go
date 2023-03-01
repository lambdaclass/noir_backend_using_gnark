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

func TestRawGateTermUnmarshalJSON(t *testing.T) {
	encodedCoefficient, _ := SampleEncodedFelt()
	multiplicand := rand.Uint32()
	multiplier := rand.Uint32()
	sum := rand.Uint32()
	mulTerms := fmt.Sprintf(`[{"coefficient":"%s","multiplicand":%d,"multiplier":%d},{"coefficient":"%s","multiplicand":%d,"multiplier":%d}]`, encodedCoefficient, multiplicand, multiplier, encodedCoefficient, multiplicand, multiplier)
	addTerms := fmt.Sprintf(`[{"coefficient":"%s","sum":%d},{"coefficient":"%s","sum":%d}]`, encodedCoefficient, sum, encodedCoefficient, sum)
	encodedConstantTerm, _ := SampleEncodedFelt()
	rawGate := fmt.Sprintf(`{"mul_terms":%s,"add_terms":%s,"constant_term":"%s"}`, mulTerms, addTerms, encodedConstantTerm)

	var r RawGate
	err := json.Unmarshal([]byte(rawGate), &r)
	if err != nil {
		log.Fatal(err)
	}

	assert.NoError(t, err)
}

func TestRawGatesTermUnmarshalJSON(t *testing.T) {
	encodedCoefficient, _ := SampleEncodedFelt()
	multiplicand := rand.Uint32()
	multiplier := rand.Uint32()
	sum := rand.Uint32()
	mulTerms := fmt.Sprintf(`[{"coefficient":"%s","multiplicand":%d,"multiplier":%d},{"coefficient":"%s","multiplicand":%d,"multiplier":%d}]`, encodedCoefficient, multiplicand, multiplier, encodedCoefficient, multiplicand, multiplier)
	addTerms := fmt.Sprintf(`[{"coefficient":"%s","sum":%d},{"coefficient":"%s","sum":%d}]`, encodedCoefficient, sum, encodedCoefficient, sum)
	encodedConstantTerm, _ := SampleEncodedFelt()
	rawGate := fmt.Sprintf(`{"mul_terms":%s,"add_terms":%s,"constant_term":"%s"}`, mulTerms, addTerms, encodedConstantTerm)
	rawGates := fmt.Sprintf(`[%s,%s]`, rawGate, rawGate)

	var r []RawGate
	err := json.Unmarshal([]byte(rawGates), &r)
	if err != nil {
		log.Fatal(err)
	}

	assert.NoError(t, err)
}
