package opcode

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"testing"

	"gnark_backend_ffi/acir/term"
	backend_helpers "gnark_backend_ffi/internal/backend"

	"github.com/stretchr/testify/assert"
)

// TODO: Test error cases.

func TestArithmeticOpcodeUnmarshalJSON(t *testing.T) {
	encodedCoefficient, _ := backend_helpers.RandomEncodedFelt()
	multiplicand := rand.Uint32()
	multiplier := rand.Uint32()
	sum := rand.Uint32()
	mulTerms := fmt.Sprintf(`[{"coefficient":"%s","multiplicand":%d,"multiplier":%d},{"coefficient":"%s","multiplicand":%d,"multiplier":%d}]`, encodedCoefficient, multiplicand, multiplier, encodedCoefficient, multiplicand, multiplier)
	addTerms := fmt.Sprintf(`[{"coefficient":"%s","sum":%d},{"coefficient":"%s","sum":%d}]`, encodedCoefficient, sum, encodedCoefficient, sum)
	encodedConstantTerm, nonEncodedConstantTerm := backend_helpers.RandomEncodedFelt()
	arithmetic_opcode := fmt.Sprintf(`{"Arithmetic": {"mul_terms":%s,"linear_combinations":%s,"q_c":"%s"}}`, mulTerms, addTerms, encodedConstantTerm)

	var r ArithmeticOpcode
	err := json.Unmarshal([]byte(arithmetic_opcode), &r)

	assert.NoError(t, err)
	assert.Equal(t, term.UncheckedDeserializeMulTerms(mulTerms), r.MulTerms)
	assert.Equal(t, term.UncheckedDeserializeSimpleTerms(addTerms), r.SimpleTerms)
	assert.Equal(t, nonEncodedConstantTerm, r.QC)
}

func TestArithmeticOpcodesTermUnmarshalJSON(t *testing.T) {
	encodedCoefficient, _ := backend_helpers.RandomEncodedFelt()
	multiplicand := rand.Uint32()
	multiplier := rand.Uint32()
	sum := rand.Uint32()
	mulTerms := fmt.Sprintf(`[{"coefficient":"%s","multiplicand":%d,"multiplier":%d},{"coefficient":"%s","multiplicand":%d,"multiplier":%d}]`, encodedCoefficient, multiplicand, multiplier, encodedCoefficient, multiplicand, multiplier)
	addTerms := fmt.Sprintf(`[{"coefficient":"%s","sum":%d},{"coefficient":"%s","sum":%d}]`, encodedCoefficient, sum, encodedCoefficient, sum)
	encodedConstantTerm, nonEncodedConstantTerm := backend_helpers.RandomEncodedFelt()
	arithmetic_opcode := fmt.Sprintf(`{"Arithmetic": {"mul_terms":%s,"linear_combinations":%s,"q_c":"%s"}}`, mulTerms, addTerms, encodedConstantTerm)
	arithmetic_opcodes := fmt.Sprintf(`[%s,%s]`, arithmetic_opcode, arithmetic_opcode)

	var r []ArithmeticOpcode
	err := json.Unmarshal([]byte(arithmetic_opcodes), &r)

	assert.NoError(t, err)
	for _, op := range r {
		assert.Equal(t, term.UncheckedDeserializeMulTerms(mulTerms), op.MulTerms)
		assert.Equal(t, term.UncheckedDeserializeSimpleTerms(addTerms), op.SimpleTerms)
		assert.Equal(t, nonEncodedConstantTerm, op.QC)
	}
}
