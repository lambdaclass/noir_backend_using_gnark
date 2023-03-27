package plonk_backend

import (
	"fmt"
	"math/big"

	fr_bn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/constraint"
	cs_bn254 "github.com/consensys/gnark/constraint/bn254"
)

// AES black box function call is not handled
func AES() {}

// AND black box function call is not handled
func AND() {}

// XOR black box function call is not handled
func XOR() {}

// RANGE black box function call is not handled
func Range() {}

// SHA256 black box function call is not handled
func SHA256() {}

// Blake2s black box function call is not handled
func Blake2s() {}

// MerkleMembership black box function call is not handled
func MerkleMembership() {}

// SchnorrVerify black box function call is not handled
func SchnorrVerify() {}

// Pedersen black box function call is not handled
func Pedersen() {}

// HashToField128Security black box function call is not handled
func HashToField128Security() {}

// EcdsaSecp256k1 black box function call is not handled
func EcdsaSecp256k1() {}

// FixedBaseScalarMul black box function call is not handled
func FixedBaseScalarMul() {}

// Keccak256 black box function call is not handled
func Keccak256() {}

// This function searches for any secret variable whose value is 1 and returns its index.
// If no secret variable has value 1 then it adds a new secret variable with value 1 and
// returns its index.
// This is an optimization to avoid adding a new secret variable with value 1 every time
// we need to add a constraint that uses 1.
func findOneIndex(sparseR1CS *cs_bn254.SparseR1CS, secretVariables fr_bn254.Vector) (int, fr_bn254.Vector) {
	one := fr_bn254.One()
	for i, v := range secretVariables {
		if v.IsOne() {
			return i, secretVariables
		}
	}

	newOne := sparseR1CS.AddSecretVariable("1")
	secretVariables = append(secretVariables, one)
	return newOne, secretVariables
}

// Generates constraints for asserting that a given value is boolean.
// It generates two constraints, one for (1 - b) and another one for (1 - b) * b
// where b is the bit being checked.
//
// bitIndex is the index of the evaluated bit in the values vector.
// sparseR1CS is the constraint system being mutated.
// secretVariables is the vector of secret variables and it is necessary because
// we're adding two new values here (one for 1 - b and another one for (1 - b) * b)
// and they could not be public because they're intermediate variables and they
// could not be internal variables because in that case we'd lose track of the
// index of these added variables.
//
// It is important to note that the values vector being mutated here are the secret
// variables (the explanation is above) and it is also important to note that this
// component or any component should be added after calling backend.HandleValues()
// because the order in which we add se public and the secret variables matters when
// using Gnark (the public variables must be added first, then the secret variables)
// and because we're adding a secret variable here we need to be sure that the
// public and secret variables are already added to the constraint system.
//
// The intuition here is for the constraints to be satisfied if and only if the
// inputs are either 1 or 0. The constraints here verifies the following:
// (1 - bit) * bit = 0
// if bit = 1 => 0 * 1 = 0
// if bit = 0 => 1 * 0 = 0
// if bit != 1 && bit != 0 => (1 - bit) * bit != 0
// TODO: Maybe these constraints could be reduced to one (b * b^2)
func assertIsBoolean(bitIndex int, sparseR1CS *cs_bn254.SparseR1CS, secretVariables fr_bn254.Vector) fr_bn254.Vector {
	var xa, xb, xc int
	var qL, qR, qO, qM1, qM2 constraint.Coeff

	ONE_WIRE, secretVariables := findOneIndex(sparseR1CS, secretVariables)

	/* 1 - b constraint */

	// 1
	qL = sparseR1CS.One()
	xa = ONE_WIRE
	// -bit
	qR = sparseR1CS.FromInterface(-1)
	xb = bitIndex
	// 1 - bit
	qO = sparseR1CS.FromInterface(-1)
	xc = sparseR1CS.AddSecretVariable("(1 - b)")

	// Add (1 - b) to the values vector so it could be recovered with xc (the index to it).
	var oneMinusBit fr_bn254.Element
	one := fr_bn254.One()
	oneMinusBit.Sub(&one, &secretVariables[bitIndex])
	secretVariables = append(secretVariables, oneMinusBit)

	oneMinusBitConstraint := constraint.SparseR1C{
		L: sparseR1CS.MakeTerm(&qL, xa),
		R: sparseR1CS.MakeTerm(&qR, xb),
		O: sparseR1CS.MakeTerm(&qO, xc),
		M: [2]constraint.Term{sparseR1CS.MakeTerm(&qM1, xa), sparseR1CS.MakeTerm(&qM2, xb)},
		K: constraint.CoeffIdZero,
	}

	sparseR1CS.AddConstraint(oneMinusBitConstraint)

	/* (1 - b) * b constraint */

	// Clean left & right selectors
	qL = sparseR1CS.FromInterface(0)
	qR = sparseR1CS.FromInterface(0)
	// (1 - b)
	qM1 = sparseR1CS.One()
	xa = xc
	// b
	qM2 = sparseR1CS.One()
	xb = bitIndex
	// (1 - b) * b
	qO = sparseR1CS.FromInterface(-1)
	xc = sparseR1CS.AddSecretVariable("(1 - b) * b")

	// Add (1 - b) * b to the values vector so it could be recovered with xc (the index to it).
	var oneMinusBitTimesBit fr_bn254.Element
	oneMinusBit.Mul(&oneMinusBit, &secretVariables[bitIndex])
	secretVariables = append(secretVariables, oneMinusBitTimesBit)

	oneMinusBitTimesBitConstraint := constraint.SparseR1C{
		L: sparseR1CS.MakeTerm(&qL, xa),
		R: sparseR1CS.MakeTerm(&qR, xb),
		O: sparseR1CS.MakeTerm(&qO, xc),
		M: [2]constraint.Term{sparseR1CS.MakeTerm(&qM1, xa), sparseR1CS.MakeTerm(&qM2, xb)},
		K: constraint.CoeffIdZero,
	}

	sparseR1CS.AddConstraint(oneMinusBitTimesBitConstraint)

	// Values must be returned because they're being mutated (new values are being added to it)
	return secretVariables
}

// Generates constraints for the bit operation AND.
//
// lhs is the index of the left hand side of the AND operation in the values vector.
// rhs is the index of the right hand side of the AND operation in the values vector.
// sparseR1CS is the constraint system being mutated.
//
// Returns a tuple with the index of the result of the operation in the secret
// variables vector.
func and(lhs int, rhs int, sparseR1CS *cs_bn254.SparseR1CS, secretVariables fr_bn254.Vector) (int, fr_bn254.Vector) {
	secretVariables = assertIsBoolean(lhs, sparseR1CS, secretVariables)
	secretVariables = assertIsBoolean(rhs, sparseR1CS, secretVariables)

	var xa, xb, xc int
	var qL, qR, qO, qM1, qM2 constraint.Coeff

	qM1 = sparseR1CS.One()
	xa = lhs
	qM2 = sparseR1CS.One()
	xb = rhs

	qO = sparseR1CS.FromInterface(-1)
	xc = sparseR1CS.AddSecretVariable("b0 * b1")

	// Add (bit_0 * bit_1) to the values vector so it could be recovered with xc (the index to it).
	var andResult fr_bn254.Element
	andResult.Mul(&secretVariables[lhs], &secretVariables[rhs])
	secretVariables = append(secretVariables, andResult)

	andConstraint := constraint.SparseR1C{
		L: sparseR1CS.MakeTerm(&qL, xa),
		R: sparseR1CS.MakeTerm(&qR, xb),
		O: sparseR1CS.MakeTerm(&qO, xc),
		M: [2]constraint.Term{sparseR1CS.MakeTerm(&qM1, xa), sparseR1CS.MakeTerm(&qM2, xb)},
		K: constraint.CoeffIdZero,
	}

	sparseR1CS.AddConstraint(andConstraint)

	return xc, secretVariables
}

func toBits(felt fr_bn254.Element, bits int, sparseR1CS *cs_bn254.SparseR1CS, secretVariables fr_bn254.Vector) ([]int, fr_bn254.Vector) {
	var feltConstant big.Int
	felt.BigInt(&feltConstant)

	feltBitsIndices := make([]int, bits)
	for i := 0; i < bits; i++ {
		bigEndianIndex := bits - 1 - i

		bit := fr_bn254.NewElement(uint64(feltConstant.Bit(i)))
		feltBitsIndices[bigEndianIndex] = sparseR1CS.AddSecretVariable(fmt.Sprintf("bit_%d", i))
		secretVariables = append(secretVariables, bit)
	}
	return feltBitsIndices, secretVariables
}

func And(lhs int, rhs int, bits int, sparseR1CS *cs_bn254.SparseR1CS, secretVariables fr_bn254.Vector) (int, fr_bn254.Vector) {
	lhsBitsIndices, secretVariables := toBits(secretVariables[lhs], bits, sparseR1CS, secretVariables)
	rhsBitsIndices, secretVariables := toBits(secretVariables[rhs], bits, sparseR1CS, secretVariables)
	resultBits := make([]big.Word, bits)

	for i := 0; i < bits; i++ {
		lhsBitIndex := lhsBitsIndices[i]
		rhsBitIndex := rhsBitsIndices[i]
		resultBit, secretVariables := and(lhsBitIndex, rhsBitIndex, sparseR1CS, secretVariables)
		resultBits[i] = big.Word(secretVariables[resultBit].Uint64())
	}

	var (
		resultBigInt big.Int
		resultFelt   fr_bn254.Element
	)

	resultBigInt.SetBits(resultBits)
	resultFelt.SetBigInt(&resultBigInt)

	resultIndex := sparseR1CS.AddSecretVariable("and_result")
	secretVariables = append(secretVariables, resultFelt)

	return resultIndex, secretVariables
}

// Generates constraints for the bit operation XOR.
//
// lhs is the index of the left hand side of the XOR operation in the values vector.
// rhs is the index of the right hand side of the XOR operation in the values vector.
// sparseR1CS is the constraint system being mutated.
//
// Returns a tuple with the index of the result of the operation in the secret
// variables vector.
func xor(lhs int, rhs int, sparseR1CS *cs_bn254.SparseR1CS, secretVariables fr_bn254.Vector) (int, fr_bn254.Vector) {
	secretVariables = assertIsBoolean(lhs, sparseR1CS, secretVariables)
	secretVariables = assertIsBoolean(rhs, sparseR1CS, secretVariables)

	var xa, xb, xc int
	var qL, qR, qO, qM1, qM2 constraint.Coeff

	// -1 * a
	qL = sparseR1CS.FromInterface(-1)
	xa = lhs
	// -1 * b
	qR = sparseR1CS.FromInterface(-1)
	xb = rhs
	// 2 * (a * b)
	qM1 = sparseR1CS.FromInterface(2)
	xa = lhs
	qM2 = sparseR1CS.One()
	xb = rhs
	// a + b - 2 * a * b
	qO = sparseR1CS.FromInterface(1)
	xc = sparseR1CS.AddSecretVariable("a + b - 2 * (a * b)")

	// Add a + b - 2 * a * b to the values vector so it could be recovered with xc (the index to it).
	var (
		aPlusB          fr_bn254.Element
		aTimesB         fr_bn254.Element
		twoTimesATimesB fr_bn254.Element
		xorResult       fr_bn254.Element
	)
	two := fr_bn254.NewElement(2)
	aPlusB.Add(&secretVariables[lhs], &secretVariables[rhs])
	aTimesB.Mul(&secretVariables[lhs], &secretVariables[rhs])
	twoTimesATimesB.Mul(&two, &aTimesB)
	// a + b - 2 * a * b
	xorResult.Sub(&aPlusB, &twoTimesATimesB)
	secretVariables = append(secretVariables, xorResult)

	andConstraint := constraint.SparseR1C{
		L: sparseR1CS.MakeTerm(&qL, xa),
		R: sparseR1CS.MakeTerm(&qR, xb),
		O: sparseR1CS.MakeTerm(&qO, xc),
		M: [2]constraint.Term{sparseR1CS.MakeTerm(&qM1, xa), sparseR1CS.MakeTerm(&qM2, xb)},
		K: constraint.CoeffIdZero,
	}

	sparseR1CS.AddConstraint(andConstraint)

	return xc, secretVariables
}

func Xor(lhs int, rhs int, bits int, sparseR1CS *cs_bn254.SparseR1CS, secretVariables fr_bn254.Vector) (int, fr_bn254.Vector) {
	lhsBitsIndices, secretVariables := toBits(secretVariables[lhs], bits, sparseR1CS, secretVariables)
	rhsBitsIndices, secretVariables := toBits(secretVariables[rhs], bits, sparseR1CS, secretVariables)
	resultBits := make([]big.Word, bits)

	for i := 0; i < bits; i++ {
		lhsBitIndex := lhsBitsIndices[i]
		rhsBitIndex := rhsBitsIndices[i]
		resultBit, _secretVariables := xor(lhsBitIndex, rhsBitIndex, sparseR1CS, secretVariables)
		secretVariables = append(secretVariables, _secretVariables...)
		resultBits[i] = big.Word(secretVariables[resultBit].Uint64())
	}

	var (
		resultBigInt big.Int
		resultFelt   fr_bn254.Element
	)

	resultBigInt.SetBits(resultBits)
	resultFelt.SetBigInt(&resultBigInt)

	resultIndex := sparseR1CS.AddSecretVariable("xor_result")
	secretVariables = append(secretVariables, resultFelt)

	return resultIndex, secretVariables
}
