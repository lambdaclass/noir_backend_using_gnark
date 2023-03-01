package structs

import (
	"encoding/json"
	"log"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TODO: Test error cases.

func TestMulTermUnmarshalJSON(t *testing.T) {
	mulTerm := `{"coefficient":"0e3ef945f56c24501196feee0cc6446900dc410d0c6a4d3b4729c4788c0716e5","multiplicand":3583776697,"multiplier":2422311469}`

	var m MulTerm
	err := json.Unmarshal([]byte(mulTerm), &m)
	if err != nil {
		log.Fatal(err)
	}

	assert.NoError(t, err)
}

func TestMulTermsUnmarshalJSON(t *testing.T) {
	mulTerms := `[{"coefficient":"0e3ef945f56c24501196feee0cc6446900dc410d0c6a4d3b4729c4788c0716e5","multiplicand":3583776697,"multiplier":2422311469},{"coefficient":"0e3ef945f56c24501196feee0cc6446900dc410d0c6a4d3b4729c4788c0716e5","multiplicand":3583776697,"multiplier":2422311469}]`

	var m []MulTerm
	err := json.Unmarshal([]byte(mulTerms), &m)
	if err != nil {
		log.Fatal(err)
	}

	assert.NoError(t, err)
}
