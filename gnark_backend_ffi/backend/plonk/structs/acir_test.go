package structs

import (
	"encoding/json"
	"fmt"
	"gnark_backend_ffi/backend"
	"math/rand"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TODO: Test error cases.

func TestACIRUnmarshalJSON(t *testing.T) {
	encodedCoefficient, _ := backend.SampleEncodedFelt()
	multiplicand := rand.Uint32()
	multiplier := rand.Uint32()
	sum := rand.Uint32()
	mulTerms := fmt.Sprintf(`[{"coefficient":"%s","multiplicand":%d,"multiplier":%d},{"coefficient":"%s","multiplicand":%d,"multiplier":%d}]`, encodedCoefficient, multiplicand, multiplier, encodedCoefficient, multiplicand, multiplier)
	addTerms := fmt.Sprintf(`[{"coefficient":"%s","sum":%d},{"coefficient":"%s","sum":%d}]`, encodedCoefficient, sum, encodedCoefficient, sum)
	encodedConstantTerm, _ := backend.SampleEncodedFelt()
	arithmetic_opcode := fmt.Sprintf(`{"mul_terms":%s,"add_terms":%s,"constant_term":"%s"}`, mulTerms, addTerms, encodedConstantTerm)
	x := rand.Uint32()
	result := rand.Uint32()
	invertDirective := fmt.Sprintf(`{"Invert": {"x":%d,"result":%d}}`, x, result)
	opcodes := fmt.Sprintf(`[%s,%s]`, arithmetic_opcode, invertDirective)
	publicInputs := fmt.Sprintf("[%d,%d,%d]", multiplicand, multiplier, sum)
	currentWitness := 1
	acirJson := fmt.Sprintf(`{"current_witness_index": %d, "opcodes": %s, "public_inputs": %s}`, currentWitness, opcodes, publicInputs)

	var a ACIR
	err := json.Unmarshal([]byte(acirJson), &a)

	assert.NoError(t, err)
	//Todo check params
}
