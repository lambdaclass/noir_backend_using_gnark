package backend

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"os"

	"gnark_backend_ffi/acir"

	"github.com/consensys/gnark-crypto/ecc"
	fr_bn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/kzg"
	kzgg "github.com/consensys/gnark-crypto/kzg"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
)

type Context struct {
	Circuit acir.ACIR
	// TODO: this should probably be a constraint.System in order to be able to
	// use more backends.
	ConstraintSystem constraint.SparseR1CS
	PublicVariables  fr_bn254.Vector
	SecretVariables  fr_bn254.Vector
	Variables        fr_bn254.Vector
	VariablesMap     map[string]int
}

func NewContext(circuit acir.ACIR, cs constraint.SparseR1CS, publicVariables fr_bn254.Vector, secretVariables fr_bn254.Vector, variables fr_bn254.Vector, variablesMap map[string]int) *Context {
	return &Context{
		Circuit:          circuit,
		ConstraintSystem: cs,
		PublicVariables:  publicVariables,
		SecretVariables:  secretVariables,
		Variables:        variables,
		VariablesMap:     variablesMap,
	}
}

func (ctx *Context) AddSecretVariable(name string, value fr_bn254.Element) (variableIndex int) {
	variableIndex = ctx.ConstraintSystem.AddSecretVariable(name)
	ctx.SecretVariables = append(ctx.SecretVariables, value)
	ctx.Variables = append(ctx.Variables, value)
	return
}

func BuildWitnesses(scalarField *big.Int, publicVariables fr_bn254.Vector, privateVariables fr_bn254.Vector, nbPublicVariables int, nbSecretVariables int) witness.Witness {
	witnessValues := make(chan any)

	go func() {
		defer close(witnessValues)
		for _, publicVariable := range publicVariables {
			witnessValues <- publicVariable
		}
		for _, privateVariable := range privateVariables {
			witnessValues <- privateVariable
		}
	}()

	witness, err := witness.New(scalarField)
	if err != nil {
		log.Fatal(err)
	}

	witness.Fill(nbPublicVariables, nbSecretVariables, witnessValues)

	return witness
}

func HandleValues(cs constraint.ConstraintSystem, values fr_bn254.Vector, publicInputsIndices []uint32) (publicVariables fr_bn254.Vector, secretVariables fr_bn254.Vector, variables fr_bn254.Vector, indexMap map[string]int) {
	indexMap = make(map[string]int)
	var index int
	for i, value := range values {
		i++
		for _, publicInput := range publicInputsIndices {
			if uint32(i) == publicInput {
				index = cs.AddPublicVariable(fmt.Sprintf("public_%d", i))
				publicVariables = append(publicVariables, value)
				indexMap[fmt.Sprint(i)] = index
			}
		}

	}
	for i, value := range values {
		i++
		if len(publicInputsIndices) > 0 {
			for _, publicInput := range publicInputsIndices {
				if uint32(i) != publicInput {
					index = cs.AddSecretVariable(fmt.Sprintf("secret_%d", i))
					secretVariables = append(secretVariables, value)
					indexMap[fmt.Sprint(i)] = index
				}
			}
		} else {
			index = cs.AddSecretVariable(fmt.Sprintf("secret_%d", i))
			secretVariables = append(secretVariables, value)
			indexMap[fmt.Sprint(i)] = index
		}
	}

	variables = append(variables, publicVariables...)
	variables = append(variables, secretVariables...)

	return
}

func getFilePath() (string, error) {
	userConfigDir, err := os.UserConfigDir()
	if err != nil {
		return userConfigDir, err
	}
	return userConfigDir + "/noir-lang/srs.hex", nil
}

func LoadSRS() (srs kzgg.SRS, err error) {
	filepath, err := getFilePath()
	if err != nil {
		return
	}

	srsEncoded, err := os.ReadFile(filepath)
	if err != nil {
		return
	}
	decodedSrs, err := hex.DecodeString(string(srsEncoded))
	if err != nil {
		return
	}

	srs = kzgg.NewSRS(ecc.BN254)
	srs.ReadFrom(bytes.NewReader(decodedSrs))

	return
}

func SaveSRS(srs kzgg.SRS) (err error) {
	// Make a hex encode of the SRS.
	var serializedSRS bytes.Buffer
	srs.WriteTo(&serializedSRS)
	encodedSRS := hex.EncodeToString(serializedSRS.Bytes())

	// Save the encoded SRS in a file named srs.hex in the user config dir.
	// We need to save the encoded SRS because the struct VerifyingKey has a pointer
	// to a SRS struct but we can't rely on a pointer because memory is volatile.
	// When we deserialize the VerifyingKey we will deserialize the SRS and insert
	// a valid pointer.
	filepath, err := getFilePath()
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(filepath, []byte(encodedSRS), 0644)

	return
}

func TryLoadSRS(curveID ecc.ID) (srs kzgg.SRS, err error) {
	// Load SRS if it is already generated.
	srs, err = LoadSRS()
	if err != nil {
		// SRS wasn't generated so we generate it.
		alpha, err2 := rand.Int(rand.Reader, curveID.ScalarField())
		if err2 != nil {
			err = err2
			return
		}
		srs, err = kzg.NewSRS(1_000_000, alpha)
		if err != nil {
			return
		}
		SaveSRS(srs)
	}
	return
}
