package plonk

import (
	"encoding/json"
	"fmt"
	"gnark_backend_ffi/backend"
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
	arithmetic_opcode := fmt.Sprintf(`{"Arithmetic": {"mul_terms":%s,"linear_combinations":%s,"q_c":"%s"}}`, mulTerms, addTerms, encodedConstantTerm)

	var r ArithmeticOpcode
	err := json.Unmarshal([]byte(arithmetic_opcode), &r)

	assert.NoError(t, err)
	assert.Equal(t, backend.UncheckedDeserializeMulTerms(mulTerms), r.MulTerms)
	assert.Equal(t, backend.UncheckedDeserializeAddTerms(addTerms), r.AddTerms)
	assert.Equal(t, nonEncodedConstantTerm, r.QC)
}

func TestArithmeticOpcodesTermUnmarshalJSON(t *testing.T) {
	encodedCoefficient, _ := backend.SampleEncodedFelt()
	multiplicand := rand.Uint32()
	multiplier := rand.Uint32()
	sum := rand.Uint32()
	mulTerms := fmt.Sprintf(`[{"coefficient":"%s","multiplicand":%d,"multiplier":%d},{"coefficient":"%s","multiplicand":%d,"multiplier":%d}]`, encodedCoefficient, multiplicand, multiplier, encodedCoefficient, multiplicand, multiplier)
	addTerms := fmt.Sprintf(`[{"coefficient":"%s","sum":%d},{"coefficient":"%s","sum":%d}]`, encodedCoefficient, sum, encodedCoefficient, sum)
	encodedConstantTerm, nonEncodedConstantTerm := backend.SampleEncodedFelt()
	arithmetic_opcode := fmt.Sprintf(`{"Arithmetic": {"mul_terms":%s,"linear_combinations":%s,"q_c":"%s"}}`, mulTerms, addTerms, encodedConstantTerm)
	arithmetic_opcodes := fmt.Sprintf(`[%s,%s]`, arithmetic_opcode, arithmetic_opcode)

	var r []ArithmeticOpcode
	err := json.Unmarshal([]byte(arithmetic_opcodes), &r)

	assert.NoError(t, err)
	for _, op := range r {
		assert.Equal(t, backend.UncheckedDeserializeMulTerms(mulTerms), op.MulTerms)
		assert.Equal(t, backend.UncheckedDeserializeAddTerms(addTerms), op.AddTerms)
		assert.Equal(t, nonEncodedConstantTerm, op.QC)
	}
}

func TestArithmeticOpcodeUnmarshalJSONMulTermCoeffError(t *testing.T) {
	encodedCoefficient, _ := backend.SampleEncodedFelt()
	mulTerms := fmt.Sprintf(`[{"c":"%s","multiplicand":0,"multiplier":0},{"coefficient":"%s","multiplicand":0,"multiplier":0}]`, encodedCoefficient, encodedCoefficient)
	addTerms := fmt.Sprintf(`[{"coefficient":"%s","sum":0},{"coefficient":"%s","sum":0}]`, encodedCoefficient, encodedCoefficient)
	arithmetic_opcode := fmt.Sprintf(`{"Arithmetic": {"mul_terms":%s,"linear_combinations":%s,"q_c":"%s"}}`, mulTerms, addTerms, encodedCoefficient)

	var r ArithmeticOpcode
	err := json.Unmarshal([]byte(arithmetic_opcode), &r)
	assert.Error(t, err)
}

func TestArithmeticOpcodeUnmarshalJSONMulTermMultiplicandError(t *testing.T) {
	encodedCoefficient, _ := backend.SampleEncodedFelt()
	mulTerms := fmt.Sprintf(`[{"coefficient":"%s","multi":0,"multiplier":0},{"coefficient":"%s","multiplicand":0,"multiplier":0}]`, encodedCoefficient, encodedCoefficient)
	addTerms := fmt.Sprintf(`[{"coefficient":"%s","sum":0},{"coefficient":"%s","sum":0}]`, encodedCoefficient, encodedCoefficient)
	arithmetic_opcode := fmt.Sprintf(`{"Arithmetic": {"mul_terms":%s,"linear_combinations":%s,"q_c":"%s"}}`, mulTerms, addTerms, encodedCoefficient)

	var r ArithmeticOpcode
	err := json.Unmarshal([]byte(arithmetic_opcode), &r)
	assert.Error(t, err)
}

func TestArithmeticOpcodeUnmarshalJSONMlTermMultiplierError(t *testing.T) {
	encodedCoefficient, _ := backend.SampleEncodedFelt()
	mulTerms := fmt.Sprintf(`[{"coefficient":"%s","multiplicand":0,"multi":0},{"coefficient":"%s","multiplicand":0,"multiplier":0}]`, encodedCoefficient, encodedCoefficient)
	addTerms := fmt.Sprintf(`[{"coefficient":"%s","sum":0},{"coefficient":"%s","sum":0}]`, encodedCoefficient, encodedCoefficient)
	arithmetic_opcode := fmt.Sprintf(`{"Arithmetic": {"mul_terms":%s,"linear_combinations":%s,"q_c":"%s"}}`, mulTerms, addTerms, encodedCoefficient)

	var r ArithmeticOpcode
	err := json.Unmarshal([]byte(arithmetic_opcode), &r)
	assert.Error(t, err)
}

func TestArithmeticOpcodeUnmarshalJSONAddTermCoeffError(t *testing.T) {
	encodedCoefficient, _ := backend.SampleEncodedFelt()
	mulTerms := fmt.Sprintf(`[{"coefficient":"%s","multiplicand":0,"multiplier":0},{"coefficient":"%s","multiplicand":0,"multiplier":0}]`, encodedCoefficient, encodedCoefficient)
	addTerms := fmt.Sprintf(`[{"coeff":"%s","sum":0},{"coefficient":"%s","sum":0}]`, encodedCoefficient, encodedCoefficient)
	arithmetic_opcode := fmt.Sprintf(`{"Arithmetic": {"mul_terms":%s,"linear_combinations":%s,"q_c":"%s"}}`, mulTerms, addTerms, encodedCoefficient)

	var r ArithmeticOpcode
	err := json.Unmarshal([]byte(arithmetic_opcode), &r)
	assert.Error(t, err)
}

func TestArithmeticOpcodeUnmarshalJSONAddTermSumError(t *testing.T) {
	encodedCoefficient, _ := backend.SampleEncodedFelt()
	mulTerms := fmt.Sprintf(`[{"coefficient":"%s","multiplicand":0,"multiplier":0},{"coefficient":"%s","multiplicand":0,"multiplier":0}]`, encodedCoefficient, encodedCoefficient)
	addTerms := fmt.Sprintf(`[{"coefficient":"%s","su":0},{"coefficient":"%s","sum":0}]`, encodedCoefficient, encodedCoefficient)
	arithmetic_opcode := fmt.Sprintf(`{"Arithmetic": {"mul_terms":%s,"linear_combinations":%s,"q_c":"%s"}}`, mulTerms, addTerms, encodedCoefficient)

	var r ArithmeticOpcode
	err := json.Unmarshal([]byte(arithmetic_opcode), &r)
	assert.Error(t, err)
}

func TestArithmeticOpcodeUnmarshalJSONMissingArithmeticKeyError(t *testing.T) {
	encodedCoefficient, _ := backend.SampleEncodedFelt()
	mulTerms := fmt.Sprintf(`[{"coefficient":"%s","multiplicand":0,"multiplier":0},{"coefficient":"%s","multiplicand":0,"multiplier":0}]`, encodedCoefficient, encodedCoefficient)
	addTerms := fmt.Sprintf(`[{"coefficient":"%s","sum":0},{"coefficient":"%s","sum":0}]`, encodedCoefficient, encodedCoefficient)
	arithmetic_opcode := fmt.Sprintf(`{"ari": {"mul_terms":%s,"linear_combinations":%s,"q_c":"%s"}}`, mulTerms, addTerms, encodedCoefficient)

	var r ArithmeticOpcode
	err := json.Unmarshal([]byte(arithmetic_opcode), &r)
	assert.Error(t, err)
}

func TestArithmeticOpcodeUnmarshalJSONMissingMulTermError(t *testing.T) {
	encodedCoefficient, _ := backend.SampleEncodedFelt()
	mulTerms := fmt.Sprintf(`[{"coefficient":"%s","multiplicand":0,"multiplier":0},{"coefficient":"%s","multiplicand":0,"multiplier":0}]`, encodedCoefficient, encodedCoefficient)
	addTerms := fmt.Sprintf(`[{"coefficient":"%s","sum":0},{"coefficient":"%s","sum":0}]`, encodedCoefficient, encodedCoefficient)
	arithmetic_opcode := fmt.Sprintf(`{"Arithmetic": {"mul":%s,"linear_combinations":%s,"q_c":"%s"}}`, mulTerms, addTerms, encodedCoefficient)

	var r ArithmeticOpcode
	err := json.Unmarshal([]byte(arithmetic_opcode), &r)
	assert.Error(t, err)
}

func TestArithmeticOpcodeUnmarshalJSONMissingLinearCombinationsError(t *testing.T) {
	encodedCoefficient, _ := backend.SampleEncodedFelt()
	mulTerms := fmt.Sprintf(`[{"coefficient":"%s","multiplicand":0,"multiplier":0},{"coefficient":"%s","multiplicand":0,"multiplier":0}]`, encodedCoefficient, encodedCoefficient)
	addTerms := fmt.Sprintf(`[{"coefficient":"%s","sum":0},{"coefficient":"%s","sum":0}]`, encodedCoefficient, encodedCoefficient)
	arithmetic_opcode := fmt.Sprintf(`{"Arithmetic": {"mul":%s,"linear":%s,"q_c":"%s"}}`, mulTerms, addTerms, encodedCoefficient)

	var r ArithmeticOpcode
	err := json.Unmarshal([]byte(arithmetic_opcode), &r)
	assert.Error(t, err)
}

func TestArithmeticOpcodeUnmarshalJSONMissingQCError(t *testing.T) {
	encodedCoefficient, _ := backend.SampleEncodedFelt()
	mulTerms := fmt.Sprintf(`[{"coefficient":"%s","multiplicand":0,"multiplier":0},{"coefficient":"%s","multiplicand":0,"multiplier":0}]`, encodedCoefficient, encodedCoefficient)
	addTerms := fmt.Sprintf(`[{"coefficient":"%s","sum":0},{"coefficient":"%s","sum":0}]`, encodedCoefficient, encodedCoefficient)
	arithmetic_opcode := fmt.Sprintf(`{"Arithmetic": {"mul":%s,"linear_combinations":%s,"a":"%s"}}`, mulTerms, addTerms, encodedCoefficient)

	var r ArithmeticOpcode
	err := json.Unmarshal([]byte(arithmetic_opcode), &r)
	assert.Error(t, err)
}
