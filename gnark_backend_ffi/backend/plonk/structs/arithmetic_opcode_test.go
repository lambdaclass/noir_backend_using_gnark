package structs

import (
	"encoding/json"
	"fmt"
	"gnark_backend_ffi/backend"
	"log"
	"math/rand"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TODO: Test error cases.

func TestArithmeticOpcodeUnmarshalJSON(t *testing.T) {
	encodedCoefficient, _ := backend.SampleEncodedFelt()
	multiplicand := rand.Uint32()
	multiplier := rand.Uint32()
	sum := rand.Uint32()
	mulTerms := fmt.Sprintf(`[{"coefficient":"%s","multiplicand":%d,"multiplier":%d},{"coefficient":"%s","multiplicand":%d,"multiplier":%d}]`, encodedCoefficient, multiplicand, multiplier, encodedCoefficient, multiplicand, multiplier)
	addTerms := fmt.Sprintf(`[{"coefficient":"%s","sum":%d},{"coefficient":"%s","sum":%d}]`, encodedCoefficient, sum, encodedCoefficient, sum)
	encodedConstantTerm, nonEncodedConstantTerm := backend.SampleEncodedFelt()
	arithmetic_opcode := fmt.Sprintf(`{"mul_terms":%s,"add_terms":%s,"constant_term":"%s"}`, mulTerms, addTerms, encodedConstantTerm)

	var r ArithmeticOpcode
	err := json.Unmarshal([]byte(arithmetic_opcode), &r)
	if err != nil {
		log.Fatal(err)
	}

	assert.NoError(t, err)
	assert.Equal(t, backend.UncheckedDeserializeMulTerms(mulTerms), r.MulTerms)
	assert.Equal(t, backend.UncheckedDeserializeAddTerms(addTerms), r.AddTerms)
	assert.Equal(t, nonEncodedConstantTerm, r.qM)
}

func TestArithmeticOpcodesTermUnmarshalJSON(t *testing.T) {
	encodedCoefficient, _ := backend.SampleEncodedFelt()
	multiplicand := rand.Uint32()
	multiplier := rand.Uint32()
	sum := rand.Uint32()
	mulTerms := fmt.Sprintf(`[{"coefficient":"%s","multiplicand":%d,"multiplier":%d},{"coefficient":"%s","multiplicand":%d,"multiplier":%d}]`, encodedCoefficient, multiplicand, multiplier, encodedCoefficient, multiplicand, multiplier)
	addTerms := fmt.Sprintf(`[{"coefficient":"%s","sum":%d},{"coefficient":"%s","sum":%d}]`, encodedCoefficient, sum, encodedCoefficient, sum)
	encodedConstantTerm, nonEncodedConstantTerm := backend.SampleEncodedFelt()
	arithmetic_opcode := fmt.Sprintf(`{"mul_terms":%s,"add_terms":%s,"constant_term":"%s"}`, mulTerms, addTerms, encodedConstantTerm)
	arithmetic_opcodes := fmt.Sprintf(`[%s,%s]`, arithmetic_opcode, arithmetic_opcode)

	var r []ArithmeticOpcode
	err := json.Unmarshal([]byte(arithmetic_opcodes), &r)
	if err != nil {
		log.Fatal(err)
	}

	assert.NoError(t, err)
	for _, op := range r {
		assert.Equal(t, backend.UncheckedDeserializeMulTerms(mulTerms), op.MulTerms)
		assert.Equal(t, backend.UncheckedDeserializeAddTerms(addTerms), op.AddTerms)
		assert.Equal(t, nonEncodedConstantTerm, op.qM)
	}
}
