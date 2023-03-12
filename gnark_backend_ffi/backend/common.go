package backend

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"gnark_backend_ffi/acir"
	"io/ioutil"
	"log"
	"math/big"
	"os"

	"github.com/consensys/gnark-crypto/ecc"
	fr_bn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/kzg"
	kzgg "github.com/consensys/gnark-crypto/kzg"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
)

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

func HandleValues(a acir.ACIR, cs constraint.ConstraintSystem, values fr_bn254.Vector) (publicVariables fr_bn254.Vector, secretVariables fr_bn254.Vector, indexMap map[string]int) {
	indexMap = make(map[string]int)
	var index int
	for i, value := range values {
		i++
		for _, publicInput := range a.PublicInputs {
			if uint32(i) == publicInput {
				index = cs.AddPublicVariable(fmt.Sprintf("public_%d", i))
				publicVariables = append(publicVariables, value)
				indexMap[fmt.Sprint(i)] = index
			}
		}

	}
	for i, value := range values {
		i++
		for _, publicInput := range a.PublicInputs {
			if uint32(i) != publicInput {
				index = cs.AddSecretVariable(fmt.Sprintf("secret_%d", i))
				secretVariables = append(secretVariables, value)
				indexMap[fmt.Sprint(i)] = index
			}
		}
	}
	return
}

func LoadSRS() (srs kzgg.SRS, err error) {
	srsEncoded, err := os.ReadFile("srs.hex")
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

	// Save the encoded SRS in a file named srs.hex.
	// We need to save the encoded SRS because the struct VerifyingKey has a pointer
	// to a SRS struct but we can't rely on a pointer because memory is volatile.
	// When we deserialize the VerifyingKey we will deserialize the SRS and insert
	// a valid pointer.
	err = ioutil.WriteFile("srs.hex", []byte(encodedSRS), 0644)

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
