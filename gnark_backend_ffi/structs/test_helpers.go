package structs

import (
	"fmt"
	"math/rand"
)

func randomAddTerm() string {
	encodedCoefficient, _ := SampleEncodedFelt()
	sum := rand.Uint32()
	return fmt.Sprintf(`{"coefficient":"%s","sum":%d}`, encodedCoefficient, sum)
}

func randomMulTerm() string {
	encodedCoefficient, _ := SampleEncodedFelt()
	multiplicand := rand.Uint32()
	multiplier := rand.Uint32()
	return fmt.Sprintf(`{"coefficient":"%s","multiplicand":%d,"multiplier":%d}`, encodedCoefficient, multiplicand, multiplier)
}

func randomAddTerms() string {
	return fmt.Sprintf(`[%s,%s]`, randomAddTerm(), randomAddTerm())
}

func randomMulTerms() string {
	return fmt.Sprintf(`[%s,%s]`, randomMulTerm(), randomMulTerm())
}

func randomRawGate() string {
	encodedConstantTerm, _ := SampleEncodedFelt()
	mulTerms := randomMulTerms()
	addTerms := randomAddTerms()

	return fmt.Sprintf(`{"mul_terms":%s,"add_terms":%s,"constant_term":"%s"}`, mulTerms, addTerms, encodedConstantTerm)
}

func randomRawGates() string {
	return fmt.Sprintf(`[%s,%s]`, randomRawGate(), randomRawGate())
}
