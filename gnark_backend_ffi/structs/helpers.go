package structs

import (
	"encoding/hex"
	"encoding/json"
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

func UncheckedDeserializeAddTerm(addTerm string) AddTerm {
	var a AddTerm
	err := json.Unmarshal([]byte(addTerm), &a)
	if err != nil {
		log.Fatal(err)
	}

	return a
}

func UncheckedDeserializeAddTerms(addTerms string) []AddTerm {
	var a []AddTerm
	err := json.Unmarshal([]byte(addTerms), &a)
	if err != nil {
		log.Fatal(err)
	}

	return a
}

func UncheckedDeserializeMulTerm(mulTerm string) MulTerm {
	var m MulTerm
	err := json.Unmarshal([]byte(mulTerm), &m)
	if err != nil {
		log.Fatal(err)
	}

	return m
}

func UncheckedDeserializeMulTerms(mulTerms string) []MulTerm {
	var m []MulTerm
	err := json.Unmarshal([]byte(mulTerms), &m)
	if err != nil {
		log.Fatal(err)
	}

	return m
}

func UncheckedDeserializeRawGate(rawGate string) RawGate {
	var r RawGate
	err := json.Unmarshal([]byte(rawGate), &r)
	if err != nil {
		log.Fatal(err)
	}

	return r
}

func UncheckedDeserializeRawGates(rawGates string) []RawGate {
	var r []RawGate
	err := json.Unmarshal([]byte(rawGates), &r)
	if err != nil {
		log.Fatal(err)
	}

	return r
}

func UncheckedDeserializeRawR1CS(rawR1CS string) RawR1CS {
	var r RawR1CS
	err := json.Unmarshal([]byte(rawR1CS), &r)
	if err != nil {
		log.Fatal(err)
	}

	return r
}

// Samples a felt and returns the encoded felt and the non-encoded felt.
func SampleEncodedFelt() (string, fr_bn254.Element) {
	var felt fr_bn254.Element
	felt.SetRandom()

	return hex.EncodeToString(felt.Marshal()), felt
}

// Samples a felts vector and returns the encoded felts and the non-encoded felts vector.
func SampleEncodedFelts() (string, fr_bn254.Vector) {
	var felt1 fr_bn254.Element
	felt1.SetRandom()

	var felt2 fr_bn254.Element
	felt2.SetRandom()

	felts := fr_bn254.Vector{felt1, felt2}

	binaryFelts, _ := felts.MarshalBinary()

	return hex.EncodeToString(binaryFelts), felts
}
