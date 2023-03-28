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

// Generates constraints for asserting that a given value is boolean.
//
// bitIndex is the index of the evaluated bit in the values vector.
// sparseR1CS is the constraint system being mutated.
// secretVariables is the vector of secret variables and it is necessary because
// we're adding two new values here (one for 1 - b and another one for (1 - b) * b)
// and they could not be public because they're intermediate variables and they
// could not be internal variables because in that case we'd lose track of the
// index of these added variables.
func assertIsBoolean(bitIndex int, sparseR1CS *cs_bn254.SparseR1CS) {
	var xa, xb, xc int
	var qL, qR, qO, qM1, qM2 constraint.Coeff

	// -bit + 1 * (bit * bit) = 0
	qL = sparseR1CS.FromInterface(-1)
	xa = bitIndex
	xb = bitIndex
	qM1 = sparseR1CS.One()
	qM2 = sparseR1CS.One()

	constraint := constraint.SparseR1C{
		L: sparseR1CS.MakeTerm(&qL, xa),
		R: sparseR1CS.MakeTerm(&qR, xb),
		O: sparseR1CS.MakeTerm(&qO, xc),
		M: [2]constraint.Term{sparseR1CS.MakeTerm(&qM1, xa), sparseR1CS.MakeTerm(&qM2, xb)},
		K: constraint.CoeffIdZero,
	}

	sparseR1CS.AddConstraint(constraint)
}

func assertIsEqual(lhs int, rhs int, sparseR1CS *cs_bn254.SparseR1CS) {
	var xa, xb, xc int
	var qL, qR, qO, qM1, qM2 constraint.Coeff

	// lhs - rhs = 0
	qL = sparseR1CS.One()
	xa = lhs
	qR = sparseR1CS.FromInterface(-1)
	xb = rhs

	constraint := constraint.SparseR1C{
		L: sparseR1CS.MakeTerm(&qL, xa),
		R: sparseR1CS.MakeTerm(&qR, xb),
		O: sparseR1CS.MakeTerm(&qO, xc),
		M: [2]constraint.Term{sparseR1CS.MakeTerm(&qM1, xa), sparseR1CS.MakeTerm(&qM2, xb)},
		K: constraint.CoeffIdZero,
	}

	sparseR1CS.AddConstraint(constraint)
}

// Generates constraints for the bit operation AND.
//
// lhs is the index of the left hand side of the AND operation in the values vector.
// rhs is the index of the right hand side of the AND operation in the values vector.
// sparseR1CS is the constraint system being mutated.
//
// Returns a tuple with the index of the result of the operation in the secret
// variables vector.
func and(lhs int, rhs int, sparseR1CS *cs_bn254.SparseR1CS, secretVariables fr_bn254.Vector, unconstrainedInputs bool) (int, fr_bn254.Vector) {
	if unconstrainedInputs {
		assertIsBoolean(lhs, sparseR1CS)
		assertIsBoolean(rhs, sparseR1CS)
	}

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

func add(augend int, addend int, sparseR1CS *cs_bn254.SparseR1CS, secretVariables fr_bn254.Vector) (int, fr_bn254.Vector) {
	var xa, xb, xc int
	var qL, qR, qO, qM1, qM2 constraint.Coeff

	qL = sparseR1CS.One()
	xa = augend
	qR = sparseR1CS.One()
	xb = addend
	qO = sparseR1CS.FromInterface(-1)
	xc = sparseR1CS.AddSecretVariable(fmt.Sprintf("(%s+%s)", sparseR1CS.VariableToString(augend), sparseR1CS.VariableToString(addend)))

	var sum fr_bn254.Element
	sum.Add(&secretVariables[augend], &secretVariables[addend])
	secretVariables = append(secretVariables, sum)

	addConstraint := constraint.SparseR1C{
		L: sparseR1CS.MakeTerm(&qL, xa),
		R: sparseR1CS.MakeTerm(&qR, xb),
		O: sparseR1CS.MakeTerm(&qO, xc),
		M: [2]constraint.Term{sparseR1CS.MakeTerm(&qM1, xa), sparseR1CS.MakeTerm(&qM2, xb)},
		K: constraint.CoeffIdZero,
	}

	sparseR1CS.AddConstraint(addConstraint)

	return xc, secretVariables
}

func mul(multiplicand int, multiplier int, sparseR1CS *cs_bn254.SparseR1CS, secretVariables fr_bn254.Vector) (int, fr_bn254.Vector) {
	var xa, xb, xc int
	var qL, qR, qO, qM1, qM2 constraint.Coeff

	qM1 = sparseR1CS.One()
	qM2 = sparseR1CS.One()
	xa = multiplicand
	xb = multiplier
	qO = sparseR1CS.FromInterface(-1)
	xc = sparseR1CS.AddSecretVariable(fmt.Sprintf("(%s*%s)", sparseR1CS.VariableToString(multiplicand), sparseR1CS.VariableToString(multiplier)))

	var product fr_bn254.Element
	product.Mul(&secretVariables[multiplicand], &secretVariables[multiplier])
	secretVariables = append(secretVariables, product)

	mulConstraint := constraint.SparseR1C{
		L: sparseR1CS.MakeTerm(&qL, xa),
		R: sparseR1CS.MakeTerm(&qR, xb),
		O: sparseR1CS.MakeTerm(&qO, xc),
		M: [2]constraint.Term{sparseR1CS.MakeTerm(&qM1, xa), sparseR1CS.MakeTerm(&qM2, xb)},
		K: constraint.CoeffIdZero,
	}

	sparseR1CS.AddConstraint(mulConstraint)

	return xc, secretVariables
}

func toBinaryConversion(felt int, bits int, sparseR1CS *cs_bn254.SparseR1CS, secretVariables fr_bn254.Vector) ([]int, fr_bn254.Vector) {
	/* Felt to binary (hint) */
	var feltConstant big.Int
	secretVariables[felt].BigInt(&feltConstant)

	feltBitsIndices := make([]int, bits)
	for i := 0; i < bits; i++ {
		bigEndianIndex := bits - 1 - i

		bit := fr_bn254.NewElement(uint64(feltConstant.Bit(i)))
		feltBitsIndices[bigEndianIndex] = sparseR1CS.AddSecretVariable(fmt.Sprintf("bit_%d", i))
		assertIsBoolean(feltBitsIndices[bigEndianIndex], sparseR1CS)
		secretVariables = append(secretVariables, bit)
	}

	/* Hint check */
	accumulator := fr_bn254.NewElement(0)
	accumulatorIndex := sparseR1CS.AddSecretVariable("accumulator")
	secretVariables = append(secretVariables, accumulator)

	var c fr_bn254.Element
	coefficientValue := big.NewInt(1)

	// These declarations are needed because if not their reference is lost in the for loop.
	var intermediateProdIndex, cIndex int

	for i := 0; i < bits; i++ {
		c.SetBigInt(coefficientValue)
		cIndex = sparseR1CS.AddSecretVariable(fmt.Sprintf("(2^%d)", i))
		secretVariables = append(secretVariables, c)
		// bits - 1 - i because we want big endian.
		bigEndianIndex := bits - 1 - i
		currentBitIndex := feltBitsIndices[bigEndianIndex]
		intermediateProdIndex, secretVariables = mul(cIndex, currentBitIndex, sparseR1CS, secretVariables)
		accumulatorIndex, secretVariables = add(accumulatorIndex, intermediateProdIndex, sparseR1CS, secretVariables)
		// Shift the coefficient for the next iteration.
		coefficientValue.Lsh(coefficientValue, 1)
	}

	// record the constraint Σ (2**i * b[i]) == a
	assertIsEqual(felt, accumulatorIndex, sparseR1CS)

	return feltBitsIndices, secretVariables
}

func fromBinaryConversion(feltBits []int, sparseR1CS *cs_bn254.SparseR1CS, secretVariables fr_bn254.Vector, unconstrainedInputs bool) (int, fr_bn254.Vector) {
	bits := len(feltBits)
	accumulator := fr_bn254.NewElement(0)
	accumulatorIndex := sparseR1CS.AddSecretVariable("accumulator")
	secretVariables = append(secretVariables, accumulator)

	var c fr_bn254.Element
	coefficientValue := big.NewInt(1)

	// These declarations are needed because if not their reference is lost in the for loop.
	var intermediateProdIndex, cIndex int

	for i := 0; i < bits; i++ {
		c.SetBigInt(coefficientValue)
		cIndex = sparseR1CS.AddSecretVariable(fmt.Sprintf("(2^%d)", i))
		secretVariables = append(secretVariables, c)
		// bits - 1 - i because we want big endian.
		bigEndianIndex := bits - 1 - i
		currentBitIndex := feltBits[bigEndianIndex]
		if unconstrainedInputs {
			assertIsBoolean(currentBitIndex, sparseR1CS)
		}
		intermediateProdIndex, secretVariables = mul(cIndex, currentBitIndex, sparseR1CS, secretVariables)
		accumulatorIndex, secretVariables = add(accumulatorIndex, intermediateProdIndex, sparseR1CS, secretVariables)
		// Shift the coefficient for the next iteration.
		coefficientValue.Lsh(coefficientValue, 1)
	}

	return accumulatorIndex, secretVariables
}

func And(lhs int, rhs int, bits int, sparseR1CS *cs_bn254.SparseR1CS, secretVariables fr_bn254.Vector) (int, fr_bn254.Vector) {
	lhsBitsIndices, secretVariables := toBinaryConversion(lhs, bits, sparseR1CS, secretVariables)
	rhsBitsIndices, secretVariables := toBinaryConversion(rhs, bits, sparseR1CS, secretVariables)
	resultBits := make([]int, bits)

	for i := 0; i < bits; i++ {
		lhsBitIndex := lhsBitsIndices[i]
		rhsBitIndex := rhsBitsIndices[i]
		// Inputs were constrained in the above `toBinaryConversion` calls.
		resultBit, _secretVariables := and(lhsBitIndex, rhsBitIndex, sparseR1CS, secretVariables, false)
		secretVariables = _secretVariables
		resultBits[i] = resultBit
	}

	return fromBinaryConversion(resultBits, sparseR1CS, secretVariables, false)
}
