package structs

import (
	"encoding/hex"
	"log"

	fr_bn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

type Witness = uint32
type Witnesses = []Witness

func DeserializeFelt(encodedFelt string) fr_bn254.Element {
	// Decode the received felt.
	decodedFelt, err := hex.DecodeString(encodedFelt)
	if err != nil {
		log.Fatal(err)
	}

	// Deserialize the decoded felt.
	var deserializedFelt fr_bn254.Element
	deserializedFelt.SetBytes(decodedFelt)

	return deserializedFelt
}

func DeserializeFelts(encodedFelts string) fr_bn254.Vector {
	// Decode the received felts.
	decodedFelts, err := hex.DecodeString(encodedFelts)
	if err != nil {
		log.Fatal(err)
	}

	// Unpack and deserialize the decoded felts.
	var deserializedFelts fr_bn254.Vector
	deserializedFelts.UnmarshalBinary(decodedFelts)

	return deserializedFelts
}
