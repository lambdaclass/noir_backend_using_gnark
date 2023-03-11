package term

import (
	"encoding/json"
	"log"
)

func UncheckedDeserializeSimpleTerm(addTerm string) SimpleTerm {
	var a SimpleTerm
	err := json.Unmarshal([]byte(addTerm), &a)
	if err != nil {
		log.Fatal(err)
	}

	return a
}

func UncheckedDeserializeSimpleTerms(addTerms string) []SimpleTerm {
	var a []SimpleTerm
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
