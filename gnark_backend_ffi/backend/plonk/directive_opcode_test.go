package plonk

import (
	"encoding/json"
	"fmt"
	"log"
	"math/rand"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TODO: Test error cases.

func TestInvertDirectiveUnmarshalJSON(t *testing.T) {
	x := rand.Uint32()
	result := rand.Uint32()
	invertDirectiveJSON := fmt.Sprintf(`{"x":%d,"result":%d}`, x, result)

	var d InvertDirective
	err := json.Unmarshal([]byte(invertDirectiveJSON), &d)
	if err != nil {
		log.Fatal(err)
	}

	assert.NoError(t, err)
	assert.Equal(t, x, d.X)
	assert.Equal(t, result, d.Result)
}

func TestDirectiveUnmarshalJSONInvertDirective(t *testing.T) {
	x := rand.Uint32()
	result := rand.Uint32()
	invertDirectiveJSON := fmt.Sprintf(`{"Invert": {"x":%d,"result":%d}}`, x, result)

	var d DirectiveOpcode
	err := json.Unmarshal([]byte(invertDirectiveJSON), &d)
	if err != nil {
		log.Fatal(err)
	}

	assert.NoError(t, err)
	assert.Equal(t, Invert, d.Name)
	assert.Equal(t, x, d.Directive.(InvertDirective).X)
	assert.Equal(t, result, d.Directive.(InvertDirective).Result)
}
