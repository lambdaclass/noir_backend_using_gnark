package main

import (
	"fmt"
	"log"
	"syscall/js"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/test"

	bls12381r1cs "github.com/consensys/gnark/constraint/bls12-381"
	"github.com/consensys/gnark/frontend"
)

type Circuit struct {
	public    []frontend.Variable `gnark:",public"`
	witnesses []frontend.Variable `gnark:",secret"`
}

func (circuit *Circuit) Define(api frontend.API) error {
	// TODO: Generate constraints
	return nil
}

func prove() js.Func {
	proveFunc := js.FuncOf(func(gates []js.Value, public_indexes []js.Value, values []js.Value) any {
		r1cs := bls12381r1cs.NewR1CS(0)

		r1cs

		constraints, r := r1cs.GetConstraints()

		bls12381r1cs.prove()
		return proof
	})
	return proveFunc
}

func verify() js.Func {
	verifyFunc := js.FuncOf(func(gates []js.Value, public_indexes []js.Value, proof []js.Value, values []js.Value) any {
		// TODO: Fill the circuit with the incoming values.
		var circuit Circuit

		// // building the circuit...
		ccs, err := frontend.Compile(ecc.BN254, scs.NewBuilder, &circuit)
		if err != nil {
			fmt.Println("circuit compilation error")
		}

		// create the necessary data for KZG.
		// This is a toy example, normally the trusted setup to build ZKG
		// has been ran before.
		// The size of the data in KZG should be the closest power of 2 bounding //
		// above max(nbConstraints, nbVariables).
		_r1cs := plonk.NewCS(ecc.BN254)
		srs, err := test.NewKZGSRS(_r1cs)
		if err != nil {
			panic(err)
		}

		witnessPublic, err := frontend.NewWitness(&circuit, ecc.BN254, frontend.PublicOnly())
		if err != nil {
			log.Fatal(err)
		}

		// public data consists the polynomials describing the constants involved
		// in the constraints, the polynomial describing the permutation ("grand
		// product argument"), and the FFT domains.
		_, vk, err := plonk.Setup(ccs, srs)
		//_, err := plonk.Setup(r1cs, kate, &publicWitness)
		if err != nil {
			log.Fatal(err)
		}

		err = plonk.Verify(proof, vk, witnessPublic)
		if err != nil {
			log.Fatal(err)
		}

		return err == nil
	})
	return verifyFunc
}

func main() {
	// Expose the functions to Javascript
	done := make(chan struct{}, 0)
	js.Global().Set("prove", prove())
	js.Global().Set("verify", verify())
	<-done
}
