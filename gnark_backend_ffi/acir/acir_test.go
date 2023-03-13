package acir

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"testing"

	"gnark_backend_ffi/acir/opcode"
	common "gnark_backend_ffi/internal"
	backend_helpers "gnark_backend_ffi/internal/backend"

	"github.com/stretchr/testify/assert"
)

// TODO: Test error cases.

func TestACIRUnmarshalJSON(t *testing.T) {
	encodedCoefficient, _ := backend_helpers.RandomEncodedFelt()
	multiplicand := rand.Uint32()
	multiplier := rand.Uint32()
	sum := rand.Uint32()
	mulTerms := fmt.Sprintf(`[{"coefficient":"%s","multiplicand":%d,"multiplier":%d},{"coefficient":"%s","multiplicand":%d,"multiplier":%d}]`, encodedCoefficient, multiplicand, multiplier, encodedCoefficient, multiplicand, multiplier)
	addTerms := fmt.Sprintf(`[{"coefficient":"%s","sum":%d},{"coefficient":"%s","sum":%d}]`, encodedCoefficient, sum, encodedCoefficient, sum)
	encodedConstantTerm, _ := backend_helpers.RandomEncodedFelt()
	arithmetic_opcode := fmt.Sprintf(`{"Arithmetic": {"mul_terms":%s,"linear_combinations":%s,"q_c":"%s"}}`, mulTerms, addTerms, encodedConstantTerm)
	x := rand.Uint32()
	result := rand.Uint32()
	invertDirective := fmt.Sprintf(`{"Invert": {"x":%d,"result":%d}}`, x, result)
	opcodes := fmt.Sprintf(`[%s,%s]`, arithmetic_opcode, invertDirective)
	publicInputs := fmt.Sprintf("[%d,%d,%d]", multiplicand, multiplier, sum)
	currentWitness := uint32(1)
	acirJson := fmt.Sprintf(`{"current_witness_index": %d, "opcodes": %s, "public_inputs": %s}`, currentWitness, opcodes, publicInputs)

	var a ACIR
	err := json.Unmarshal([]byte(acirJson), &a)
	assert.NoError(t, err)
	assert.Equal(t, currentWitness, a.CurrentWitness)
	assert.Equal(t, opcode.UncheckedDeserializeOpcodes(opcodes), a.Opcodes)
	assert.Equal(t, common.Witnesses{multiplicand, multiplier, sum}, a.PublicInputs)
}
