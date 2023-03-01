package structs

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TODO: Test error cases.

func TestRawR1CSTermUnmarshalJSON(t *testing.T) {
	multiplicand := rand.Uint32()
	multiplier := rand.Uint32()
	sum := rand.Uint32()
	mulTerms := fmt.Sprintf(`[{"coefficient":"0e3ef945f56c24501196feee0cc6446900dc410d0c6a4d3b4729c4788c0716e5","multiplicand":%d,"multiplier":%d},{"coefficient":"0e3ef945f56c24501196feee0cc6446900dc410d0c6a4d3b4729c4788c0716e5","multiplicand":%d,"multiplier":%d}]`, multiplicand, multiplier, multiplicand, multiplier)
	addTerms := fmt.Sprintf(`[{"coefficient":"0e3ef945f56c24501196feee0cc6446900dc410d0c6a4d3b4729c4788c0716e5","sum":%d},{"coefficient":"0e3ef945f56c24501196feee0cc6446900dc410d0c6a4d3b4729c4788c0716e5","sum":%d}]`, sum, sum)
	constantTerm := "0e3ef945f56c24501196feee0cc6446900dc410d0c6a4d3b4729c4788c0716e5"
	rawGate := fmt.Sprintf(`{"mul_terms":%s,"add_terms":%s,"constant_term":"%s"}`, mulTerms, addTerms, constantTerm)
	rawGates := fmt.Sprintf(`[%s,%s]`, rawGate, rawGate)
	publicInputs := fmt.Sprintf("[%d,%d,%d]", multiplicand, multiplier, sum)
	values := "000000020e863ed5c2ba04f5a88c64ad335acb2df798d830db50d760c1359328fd39c6380cf4783484cb019ebb7128d66d1009d0dc3b48acd936a157037af55753e9bd32"
	numVariables := rand.Uint64()
	numConstraints := rand.Uint64()
	rawR1CS := fmt.Sprintf(`{"gates":%s,"public_inputs":%s,"values":"%s","num_variables":%d,"num_constraints":%d}`, rawGates, publicInputs, values, numVariables, numConstraints)

	var r RawR1CS
	err := json.Unmarshal([]byte(rawR1CS), &r)

	assert.NoError(t, err)
}
