package plonk

import (
	"fmt"
	"gnark_backend_ffi/acir"
	"log"

	acir_opcode "gnark_backend_ffi/acir/opcode"

	fr_bn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/constraint"
	cs_bn254 "github.com/consensys/gnark/constraint/bn254"
)

// TODO: Refactor this function so it is generic for all systems and move it to
// a common.go module in the backend directory.
func handleValues(a acir.ACIR, sparseR1CS constraint.SparseR1CS, values fr_bn254.Vector) (publicVariables fr_bn254.Vector, secretVariables fr_bn254.Vector, indexMap map[string]int) {
	indexMap = make(map[string]int)
	var index int
	// _ = sparseR1CS.AddPublicVariable("1")
	for i, value := range values {
		i++
		for _, publicInput := range a.PublicInputs {
			if uint32(i) == publicInput {
				index = sparseR1CS.AddPublicVariable(fmt.Sprintf("public_%d", i))
				publicVariables = append(publicVariables, value)
				indexMap[fmt.Sprint(i)] = index
			}
		}

	}
	for i, value := range values {
		i++
		for _, publicInput := range a.PublicInputs {
			if uint32(i) != publicInput {
				index = sparseR1CS.AddSecretVariable(fmt.Sprintf("secret_%d", i))
				secretVariables = append(secretVariables, value)
				indexMap[fmt.Sprint(i)] = index
			}
		}
	}
	return
}

func handleOpcodes(a acir.ACIR, sparseR1CS constraint.SparseR1CS, indexMap map[string]int) {
	for _, opcode := range a.Opcodes {
		switch opcode := opcode.Data.(type) {
		case *acir_opcode.ArithmeticOpcode:
			var xa, xb, xc int
			var qL, qR, qO, qC, qM constraint.Coeff

			// Case qM⋅(xa⋅xb)
			if len(opcode.MulTerms) != 0 {
				mulTerm := opcode.MulTerms[0]
				qM = sparseR1CS.FromInterface(mulTerm.Coefficient)
				xa = indexMap[fmt.Sprint(int(mulTerm.MultiplicandIndex))]
				xb = indexMap[fmt.Sprint(int(mulTerm.MultiplierIndex))]
			}

			// Case qO⋅xc
			if len(opcode.SimpleTerms) == 1 {
				qOwOTerm := opcode.SimpleTerms[0]
				qO = sparseR1CS.FromInterface(qOwOTerm.Coefficient)
				xc = indexMap[fmt.Sprint(int(qOwOTerm.VariableIndex))]
			}

			// Case qL⋅xa + qR⋅xb
			if len(opcode.SimpleTerms) == 2 {
				// qL⋅xa
				qLwLTerm := opcode.SimpleTerms[0]
				qL = sparseR1CS.FromInterface(qLwLTerm.Coefficient)
				xa = indexMap[fmt.Sprint(int(qLwLTerm.VariableIndex))]
				// qR⋅xb
				qRwRTerm := opcode.SimpleTerms[1]
				qR = sparseR1CS.FromInterface(qRwRTerm.Coefficient)
				xb = indexMap[fmt.Sprint(int(qRwRTerm.VariableIndex))]
			}

			// Case qL⋅xa + qR⋅xb + qO⋅xc
			if len(opcode.SimpleTerms) == 3 {
				// qL⋅xa
				qLwLTerm := opcode.SimpleTerms[0]
				qL = sparseR1CS.FromInterface(qLwLTerm.Coefficient)
				xa = indexMap[fmt.Sprint(int(qLwLTerm.VariableIndex))]
				// qR⋅xb
				qRwRTerm := opcode.SimpleTerms[1]
				qR = sparseR1CS.FromInterface(qRwRTerm.Coefficient)
				xb = indexMap[fmt.Sprint(int(qRwRTerm.VariableIndex))]
				// qO⋅xc
				qOwOTerm := opcode.SimpleTerms[2]
				qO = sparseR1CS.FromInterface(qOwOTerm.Coefficient)
				xc = indexMap[fmt.Sprint(int(qOwOTerm.VariableIndex))]
			}

			// Add the qC term
			qC = sparseR1CS.FromInterface(opcode.QC)

			K := sparseR1CS.MakeTerm(&qC, 0)
			K.MarkConstant()

			constraint := constraint.SparseR1C{
				L: sparseR1CS.MakeTerm(&qL, xa),
				R: sparseR1CS.MakeTerm(&qR, xb),
				O: sparseR1CS.MakeTerm(&qO, xc),
				M: [2]constraint.Term{sparseR1CS.MakeTerm(&qM, xa), sparseR1CS.MakeTerm(&qM, xb)},
				K: K.CoeffID(),
			}

			sparseR1CS.AddConstraint(constraint)
			break
		case *acir_opcode.DirectiveOpcode:
			break
		default:
			log.Fatal("unknown opcode type")
		}
	}
}

// TODO: Make this a method for acir.ACIR.
// qL⋅xa + qR⋅xb + qO⋅xc + qM⋅(xa⋅xb) + qC == 0
func BuildSparseR1CS(a acir.ACIR, values fr_bn254.Vector) (*cs_bn254.SparseR1CS, fr_bn254.Vector, fr_bn254.Vector) {
	sparseR1CS := cs_bn254.NewSparseR1CS(int(a.CurrentWitness) - 1)

	publicVariables, secretVariables, indexMap := handleValues(a, sparseR1CS, values)
	handleOpcodes(a, sparseR1CS, indexMap)

	return sparseR1CS, publicVariables, secretVariables
}
