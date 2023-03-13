package backend

import (
	"bytes"
	"encoding/hex"
	"log"

	"github.com/consensys/gnark-crypto/ecc"
	fr_bn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/backend/plonk"
)

func DeserializeFelt(encodedFelt string) (felt fr_bn254.Element) {
	// Decode the received felt.
	decodedFelt, err := hex.DecodeString(encodedFelt)
	if err != nil {
		log.Fatal(err)
	}
	// Deserialize the decoded felt.
	felt.SetBytes(decodedFelt)
	return
}

func DeserializeFelts(encodedFelts string) (felts fr_bn254.Vector) {
	// Decode the received felts.
	decodedFelts, err := hex.DecodeString(encodedFelts)
	if err != nil {
		log.Fatal(err)
	}
	// Unpack and deserialize the decoded felts.
	felts.UnmarshalBinary(decodedFelts)
	return
}

func DeserializeProof(serializedProof string, curveID ecc.ID) (p plonk.Proof) {
	// Deserialize proof.
	p = plonk.NewProof(curveID)
	decodedProof, err := hex.DecodeString(serializedProof)
	if err != nil {
		log.Fatal(err)
	}
	_, err = p.ReadFrom(bytes.NewReader(decodedProof))
	if err != nil {
		log.Fatal(err)
	}
	return
}

func DeserializeProvingKey(encodedProvingKey string, curveID ecc.ID) (pk plonk.ProvingKey) {
	pk = plonk.NewProvingKey(curveID)
	decodedProvingKey, err := hex.DecodeString(encodedProvingKey)
	if err != nil {
		log.Fatal(err)
	}
	_, err = pk.ReadFrom(bytes.NewReader([]byte(decodedProvingKey)))
	if err != nil {
		log.Fatal(err)
	}
	return
}

func DeserializeVerifyingKey(serializedVerifyingKey string, curveID ecc.ID) (vk plonk.VerifyingKey) {
	vk = plonk.NewVerifyingKey(curveID)
	decodedVerifyingKey, err := hex.DecodeString(serializedVerifyingKey)
	if err != nil {
		log.Fatal(err)
	}
	_, err = vk.ReadFrom(bytes.NewReader(decodedVerifyingKey))
	if err != nil {
		log.Fatal(err)
	}
	return
}

func SerializeProof(proof plonk.Proof) (p string) {
	var serialized_proof bytes.Buffer
	proof.WriteTo(&serialized_proof)
	p = hex.EncodeToString(serialized_proof.Bytes())
	return
}

func SerializeProvingKey(provingKey plonk.ProvingKey) (pk string) {
	var serializedProvingKey bytes.Buffer
	provingKey.WriteTo(&serializedProvingKey)
	pk = hex.EncodeToString(serializedProvingKey.Bytes())
	return
}

func SerializeVerifyingKey(verifyingKey plonk.VerifyingKey) (vk string) {
	var serializedProvingKey bytes.Buffer
	verifyingKey.WriteTo(&serializedProvingKey)
	vk = hex.EncodeToString(serializedProvingKey.Bytes())
	return
}

// Samples a felt and returns the encoded felt and the non-encoded felt.
func RandomEncodedFelt() (string, fr_bn254.Element) {
	var felt fr_bn254.Element
	felt.SetRandom()

	return hex.EncodeToString(felt.Marshal()), felt
}

// Samples a felts vector and returns the encoded felts and the non-encoded felts vector.
func RandomEncodedFelts() (string, fr_bn254.Vector) {
	var felt1 fr_bn254.Element
	felt1.SetRandom()

	var felt2 fr_bn254.Element
	felt2.SetRandom()

	felts := fr_bn254.Vector{felt1, felt2}

	binaryFelts, _ := felts.MarshalBinary()

	return hex.EncodeToString(binaryFelts), felts
}
