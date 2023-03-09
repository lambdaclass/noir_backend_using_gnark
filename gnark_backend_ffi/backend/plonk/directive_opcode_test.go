package groth16

import (
	"encoding/json"
	"fmt"
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

	assert.NoError(t, err)
	assert.Equal(t, Invert, d.Name)
	assert.Equal(t, x, d.Directive.(InvertDirective).X)
	assert.Equal(t, result, d.Directive.(InvertDirective).Result)
}

func TestDirectiveUnmarshalJSONNonExistingDirective(t *testing.T) {
	directive := `{"Doesntexist": {"x": 0 ,"result": 0 }}`

	var d DirectiveOpcode
	err := json.Unmarshal([]byte(directive), &d)
	assert.Error(t, err)
}

func TestDirectiveUnmarshalJSONInvertNoX(t *testing.T) {
	directive := `{"Invert": {"result": 0}}`

	var d DirectiveOpcode
	err := json.Unmarshal([]byte(directive), &d)
	assert.Error(t, err)
}

func TestDirectiveUnmarshalJSONInvertNoResult(t *testing.T) {
	directive := `{"Invert": {"x": 0}}`

	var d DirectiveOpcode
	err := json.Unmarshal([]byte(directive), &d)
	assert.Error(t, err)
}
