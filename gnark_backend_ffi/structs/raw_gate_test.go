package structs

import (
	"encoding/json"
	"fmt"
	"log"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TODO: Test error cases.

func TestRawGateTermUnmarshalJSON(t *testing.T) {
	mulTerms := `[{"coefficient":"0e3ef945f56c24501196feee0cc6446900dc410d0c6a4d3b4729c4788c0716e5","multiplicand":3583776697,"multiplier":2422311469},{"coefficient":"0e3ef945f56c24501196feee0cc6446900dc410d0c6a4d3b4729c4788c0716e5","multiplicand":3583776697,"multiplier":2422311469}]`
	addTerms := `[{"coefficient":"0e3ef945f56c24501196feee0cc6446900dc410d0c6a4d3b4729c4788c0716e5","sum":2422311469},{"coefficient":"0e3ef945f56c24501196feee0cc6446900dc410d0c6a4d3b4729c4788c0716e5","sum":3583776697}]`
	constantTerm := "0e3ef945f56c24501196feee0cc6446900dc410d0c6a4d3b4729c4788c0716e5"
	rawGate := fmt.Sprintf(`{"mul_terms":%s,"add_terms":%s,"constant_term":"%s"}`, mulTerms, addTerms, constantTerm)

	var r RawGate
	err := json.Unmarshal([]byte(rawGate), &r)
	if err != nil {
		log.Fatal(err)
	}

	assert.NoError(t, err)
}

func TestRawGatesTermUnmarshalJSON(t *testing.T) {
	mulTerms := `[{"coefficient":"0e3ef945f56c24501196feee0cc6446900dc410d0c6a4d3b4729c4788c0716e5","multiplicand":3583776697,"multiplier":2422311469},{"coefficient":"0e3ef945f56c24501196feee0cc6446900dc410d0c6a4d3b4729c4788c0716e5","multiplicand":3583776697,"multiplier":2422311469}]`
	addTerms := `[{"coefficient":"0e3ef945f56c24501196feee0cc6446900dc410d0c6a4d3b4729c4788c0716e5","sum":2422311469},{"coefficient":"0e3ef945f56c24501196feee0cc6446900dc410d0c6a4d3b4729c4788c0716e5","sum":3583776697}]`
	constantTerm := "0e3ef945f56c24501196feee0cc6446900dc410d0c6a4d3b4729c4788c0716e5"
	rawGate := fmt.Sprintf(`{"mul_terms":%s,"add_terms":%s,"constant_term":"%s"}`, mulTerms, addTerms, constantTerm)
	rawGates := fmt.Sprintf(`[%s,%s]`, rawGate, rawGate)

	var r []RawGate
	err := json.Unmarshal([]byte(rawGates), &r)
	if err != nil {
		log.Fatal(err)
	}

	assert.NoError(t, err)
}
