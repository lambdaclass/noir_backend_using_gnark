package groth16

import (
	"fmt"
	"gnark_backend_ffi/backend"
	"math/rand"
)

func RandomAddTerm() string {
	encodedCoefficient, _ := backend.SampleEncodedFelt()
	sum := rand.Uint32()
	return fmt.Sprintf(`{"coefficient":"%s","sum":%d}`, encodedCoefficient, sum)
}

func RandomMulTerm() string {
	encodedCoefficient, _ := backend.SampleEncodedFelt()
	multiplicand := rand.Uint32()
	multiplier := rand.Uint32()
	return fmt.Sprintf(`{"coefficient":"%s","multiplicand":%d,"multiplier":%d}`, encodedCoefficient, multiplicand, multiplier)
}

func RandomAddTerms() string {
	return fmt.Sprintf(`[%s,%s]`, RandomAddTerm(), RandomAddTerm())
}

func RandomMulTerms() string {
	return fmt.Sprintf(`[%s,%s]`, RandomMulTerm(), RandomMulTerm())
}

func RandomRawGate() string {
	encodedConstantTerm, _ := backend.SampleEncodedFelt()
	mulTerms := RandomMulTerms()
	addTerms := RandomAddTerms()

	return fmt.Sprintf(`{"mul_terms":%s,"add_terms":%s,"constant_term":"%s"}`, mulTerms, addTerms, encodedConstantTerm)
}

func RandomRawGates() string {
	return fmt.Sprintf(`[%s,%s]`, RandomRawGate(), RandomRawGate())
}
