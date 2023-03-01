package structs

import (
	"encoding/json"
	"log"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TODO: Test error cases.

func TestAddTermUnmarshalJSON(t *testing.T) {
	addTerm := `{"coefficient":"0e3ef945f56c24501196feee0cc6446900dc410d0c6a4d3b4729c4788c0716e5","sum":2422311469}`

	var a AddTerm
	err := json.Unmarshal([]byte(addTerm), &a)
	if err != nil {
		log.Fatal(err)
	}

	assert.NoError(t, err)
}

func TestAddTermsUnmarshalJSON(t *testing.T) {
	addTerms := `[{"coefficient":"0e3ef945f56c24501196feee0cc6446900dc410d0c6a4d3b4729c4788c0716e5","sum":2422311469},{"coefficient":"0e3ef945f56c24501196feee0cc6446900dc410d0c6a4d3b4729c4788c0716e5","sum":3583776697}]`

	var a []AddTerm
	err := json.Unmarshal([]byte(addTerms), &a)
	if err != nil {
		log.Fatal(err)
	}

	assert.NoError(t, err)
}
