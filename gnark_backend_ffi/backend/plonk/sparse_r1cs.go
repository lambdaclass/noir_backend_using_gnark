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
func BuildSparseR1CS(circuit acir.ACIR, values fr_bn254.Vector) (*cs_bn254.SparseR1CS, fr_bn254.Vector, fr_bn254.Vector) {
	sparseR1CS := cs_bn254.NewSparseR1CS(int(circuit.CurrentWitness) - 1)

	publicVariables, secretVariables, indexMap := backend.HandleValues(circuit, sparseR1CS, values)
	handleOpcodes(circuit, sparseR1CS, indexMap)

	return sparseR1CS, publicVariables, secretVariables
}
