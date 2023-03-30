package plonk_backend

import (
	"fmt"
	"log"

	"gnark_backend_ffi/acir"
	acir_opcode "gnark_backend_ffi/acir/opcode"
	"gnark_backend_ffi/backend"

	fr_bn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/constraint"
	cs_bn254 "github.com/consensys/gnark/constraint/bn254"
)

// TODO: Make this a method for acir.ACIR.
// qL⋅xa + qR⋅xb + qO⋅xc + qM⋅(xa⋅xb) + qC == 0
func BuildSparseR1CS(circuit acir.ACIR, values fr_bn254.Vector) (*cs_bn254.SparseR1CS, fr_bn254.Vector, fr_bn254.Vector) {
	sparseR1CS := cs_bn254.NewSparseR1CS(int(circuit.CurrentWitness) - 1)
	publicVariables, secretVariables, variables, variablesMap := backend.HandleValues(sparseR1CS, values, circuit.PublicInputs)

	ctx := backend.NewContext(circuit, sparseR1CS, variables, publicVariables, secretVariables, variablesMap)

	addedSecretVariables := handleOpcodes(ctx)
	secretVariables = append(secretVariables, addedSecretVariables...)

	return sparseR1CS, publicVariables, secretVariables
}

func handleOpcodes(ctx *backend.Context) (addedSecretVariables fr_bn254.Vector) {
	for _, opcode := range ctx.Circuit.Opcodes {
		switch opcode := opcode.Data.(type) {
		case *acir_opcode.ArithmeticOpcode:
			handleArithmeticOpcode(ctx, opcode)
			break
		case *acir_opcode.BlackBoxFunction:
			handleBlackBoxFunctionOpcode(ctx, opcode)
			break
		case *acir_opcode.DirectiveOpcode:
			break
		default:
			log.Fatal("unknown opcode type")
		}
	}
	return
}

func handleArithmeticOpcode(ctx *backend.Context, a *acir_opcode.ArithmeticOpcode) {
	var xa, xb, xc int
	var qL, qR, qO, qC, qM1, qM2 constraint.Coeff

	// Case qM⋅(xa⋅xb)
	if len(a.MulTerms) != 0 {
		mulTerm := a.MulTerms[0]
		qM1 = ctx.ConstraintSystem.FromInterface(mulTerm.Coefficient)
		qM2 = ctx.ConstraintSystem.FromInterface(1)
		xa = ctx.VariablesMap[fmt.Sprint(int(mulTerm.MultiplicandIndex))]
		xb = ctx.VariablesMap[fmt.Sprint(int(mulTerm.MultiplierIndex))]
	}

	// Case qO⋅xc
	if len(a.SimpleTerms) == 1 {
		qOwOTerm := a.SimpleTerms[0]
		qO = ctx.ConstraintSystem.FromInterface(qOwOTerm.Coefficient)
		xc = ctx.VariablesMap[fmt.Sprint(int(qOwOTerm.VariableIndex))]
	}

	// Case qL⋅xa + qR⋅xb
	if len(a.SimpleTerms) == 2 {
		// qL⋅xa
		qLwLTerm := a.SimpleTerms[0]
		qL = ctx.ConstraintSystem.FromInterface(qLwLTerm.Coefficient)
		xa = ctx.VariablesMap[fmt.Sprint(int(qLwLTerm.VariableIndex))]
		// qR⋅xb
		qRwRTerm := a.SimpleTerms[1]
		qR = ctx.ConstraintSystem.FromInterface(qRwRTerm.Coefficient)
		xb = ctx.VariablesMap[fmt.Sprint(int(qRwRTerm.VariableIndex))]
	}

	// Case qL⋅xa + qR⋅xb + qO⋅xc
	if len(a.SimpleTerms) == 3 {
		// qL⋅xa
		qLwLTerm := a.SimpleTerms[0]
		qL = ctx.ConstraintSystem.FromInterface(qLwLTerm.Coefficient)
		xa = ctx.VariablesMap[fmt.Sprint(int(qLwLTerm.VariableIndex))]
		// qR⋅xb
		qRwRTerm := a.SimpleTerms[1]
		qR = ctx.ConstraintSystem.FromInterface(qRwRTerm.Coefficient)
		xb = ctx.VariablesMap[fmt.Sprint(int(qRwRTerm.VariableIndex))]
		// qO⋅xc
		qOwOTerm := a.SimpleTerms[2]
		qO = ctx.ConstraintSystem.FromInterface(qOwOTerm.Coefficient)
		xc = ctx.VariablesMap[fmt.Sprint(int(qOwOTerm.VariableIndex))]
	}

	// Add the qC term
	qC = ctx.ConstraintSystem.FromInterface(a.QC)

	K := ctx.ConstraintSystem.MakeTerm(&qC, 0)
	K.MarkConstant()

	constraint := constraint.SparseR1C{
		L: ctx.ConstraintSystem.MakeTerm(&qL, xa),
		R: ctx.ConstraintSystem.MakeTerm(&qR, xb),
		O: ctx.ConstraintSystem.MakeTerm(&qO, xc),
		M: [2]constraint.Term{ctx.ConstraintSystem.MakeTerm(&qM1, xa), ctx.ConstraintSystem.MakeTerm(&qM2, xb)},
		K: K.CoeffID(),
	}

	ctx.ConstraintSystem.AddConstraint(constraint)
}

func handleBlackBoxFunctionOpcode(ctx *backend.Context, bbf *acir_opcode.BlackBoxFunction) {
	switch bbf.Name {
	case acir_opcode.AES:
		AES()
		break
	case acir_opcode.AND:
		AND(ctx, bbf)
		break
	case acir_opcode.XOR:
		// XOR(bbf, sparseR1CS, variables)
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
}
