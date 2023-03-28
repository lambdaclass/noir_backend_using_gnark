package plonk_backend

import (
	"fmt"
	"gnark_backend_ffi/acir"
	"gnark_backend_ffi/backend"
	"log"

	acir_opcode "gnark_backend_ffi/acir/opcode"

	fr_bn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/constraint"
	cs_bn254 "github.com/consensys/gnark/constraint/bn254"
)

// TODO: Make this a method for acir.ACIR.
// qL⋅xa + qR⋅xb + qO⋅xc + qM⋅(xa⋅xb) + qC == 0
func BuildSparseR1CS(circuit acir.ACIR, values fr_bn254.Vector) (*cs_bn254.SparseR1CS, fr_bn254.Vector, fr_bn254.Vector) {
	sparseR1CS := cs_bn254.NewSparseR1CS(int(circuit.CurrentWitness) - 1)

	publicVariables, secretVariables, variables, variablesMap := backend.HandleValues(sparseR1CS, values, circuit.PublicInputs)
	addedSecretVariables := handleOpcodes(circuit, sparseR1CS, variables, variablesMap)
	secretVariables = append(secretVariables, addedSecretVariables...)

	return sparseR1CS, publicVariables, secretVariables
}

func handleOpcodes(a acir.ACIR, sparseR1CS constraint.SparseR1CS, variables fr_bn254.Vector, variablesMap map[string]int) (addedSecretVariables fr_bn254.Vector) {
	for _, opcode := range a.Opcodes {
		switch opcode := opcode.Data.(type) {
		case *acir_opcode.ArithmeticOpcode:
			handleArithmeticOpcode(opcode, sparseR1CS, variablesMap)
			break
		case *acir_opcode.BlackBoxFunction:
			addedSecretVariables = handleBlackBoxFunctionOpcode(opcode, sparseR1CS, variables)
			break
		case *acir_opcode.DirectiveOpcode:
			break
		default:
			log.Fatal("unknown opcode type")
		}
	}
	return
}

func handleArithmeticOpcode(a *acir_opcode.ArithmeticOpcode, sparseR1CS constraint.SparseR1CS, indexMap map[string]int) {
	var xa, xb, xc int
	var qL, qR, qO, qC, qM1, qM2 constraint.Coeff

	// Case qM⋅(xa⋅xb)
	if len(a.MulTerms) != 0 {
		mulTerm := a.MulTerms[0]
		qM1 = sparseR1CS.FromInterface(mulTerm.Coefficient)
		qM2 = sparseR1CS.FromInterface(1)
		xa = indexMap[fmt.Sprint(int(mulTerm.MultiplicandIndex))]
		xb = indexMap[fmt.Sprint(int(mulTerm.MultiplierIndex))]
	}

	// Case qO⋅xc
	if len(a.SimpleTerms) == 1 {
		qOwOTerm := a.SimpleTerms[0]
		qO = sparseR1CS.FromInterface(qOwOTerm.Coefficient)
		xc = indexMap[fmt.Sprint(int(qOwOTerm.VariableIndex))]
	}

	// Case qL⋅xa + qR⋅xb
	if len(a.SimpleTerms) == 2 {
		// qL⋅xa
		qLwLTerm := a.SimpleTerms[0]
		qL = sparseR1CS.FromInterface(qLwLTerm.Coefficient)
		xa = indexMap[fmt.Sprint(int(qLwLTerm.VariableIndex))]
		// qR⋅xb
		qRwRTerm := a.SimpleTerms[1]
		qR = sparseR1CS.FromInterface(qRwRTerm.Coefficient)
		xb = indexMap[fmt.Sprint(int(qRwRTerm.VariableIndex))]
	}

	// Case qL⋅xa + qR⋅xb + qO⋅xc
	if len(a.SimpleTerms) == 3 {
		// qL⋅xa
		qLwLTerm := a.SimpleTerms[0]
		qL = sparseR1CS.FromInterface(qLwLTerm.Coefficient)
		xa = indexMap[fmt.Sprint(int(qLwLTerm.VariableIndex))]
		// qR⋅xb
		qRwRTerm := a.SimpleTerms[1]
		qR = sparseR1CS.FromInterface(qRwRTerm.Coefficient)
		xb = indexMap[fmt.Sprint(int(qRwRTerm.VariableIndex))]
		// qO⋅xc
		qOwOTerm := a.SimpleTerms[2]
		qO = sparseR1CS.FromInterface(qOwOTerm.Coefficient)
		xc = indexMap[fmt.Sprint(int(qOwOTerm.VariableIndex))]
	}

	// Add the qC term
	qC = sparseR1CS.FromInterface(a.QC)

	K := sparseR1CS.MakeTerm(&qC, 0)
	K.MarkConstant()

	constraint := constraint.SparseR1C{
		L: sparseR1CS.MakeTerm(&qL, xa),
		R: sparseR1CS.MakeTerm(&qR, xb),
		O: sparseR1CS.MakeTerm(&qO, xc),
		M: [2]constraint.Term{sparseR1CS.MakeTerm(&qM1, xa), sparseR1CS.MakeTerm(&qM2, xb)},
		K: K.CoeffID(),
	}

	sparseR1CS.AddConstraint(constraint)
}

func handleBlackBoxFunctionOpcode(bbf *acir_opcode.BlackBoxFunction, sparseR1CS constraint.SparseR1CS, variables fr_bn254.Vector) (addedSecretVariables fr_bn254.Vector) {
	switch bbf.Name {
	case acir_opcode.AES:
		AES()
		break
	case acir_opcode.AND:
		addedSecretVariables = AND(bbf, sparseR1CS, variables)
		break
	case acir_opcode.XOR:
		addedSecretVariables = XOR(bbf, sparseR1CS, variables)
		break
	case acir_opcode.RANGE:
		Range()
		break
	case acir_opcode.SHA256:
		SHA256()
		break
	case acir_opcode.Blake2s:
		Blake2s()
		break
	case acir_opcode.MerkleMembership:
		MerkleMembership()
		break
	case acir_opcode.SchnorrVerify:
		SchnorrVerify()
		break
	case acir_opcode.Pedersen:
		Pedersen()
		break
	case acir_opcode.HashToField128Security:
		HashToField128Security()
		break
	case acir_opcode.EcdsaSecp256k1:
		EcdsaSecp256k1()
		break
	case acir_opcode.FixedBaseScalarMul:
		FixedBaseScalarMul()
		break
	case acir_opcode.Keccak256:
		Keccak256()
		break
	}
	return
}
