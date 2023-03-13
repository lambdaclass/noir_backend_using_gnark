# Using gnark as a backend for Noir

If you want to develop a backend for Noir, basically what you need to do is to translate an ACIR (Abstract Circuit Intermediate Representation) to something that your backend could understand.
The prerequisites for this are to have certain knowledge about ACIR and its codebase, and the backend that you are going to support.
In this case, the backend is [gnark](https://github.com/ConsenSys/gnark). Written in Go, gnark is a fast zk-SNARK library that offers a high-level API to design circuits. This library is open-source and developed under the Apache 2.0 license.

## Overview

```mermaid
flowchart
    N[Noir] --ACIR--> BR[Backend in gnark wrapper in Rust]
    BR[Backend in gnark wrapper written in Rust] --Raw R1CS--> B[Concrete Backend]
    subgraph B[Concrete Backend]
        direction TB
        BW[WASM/FFI] --> BG[Backend in gnark written in Go]
    end
```

### Backend wrapper written in Rust

This module is needed because Noir's backend has to be written in Rust and we want to develop one using gnark which is written in Go.

This Rust module is basically in charge of implementing the trait `Backend` for a given type which we've named `Gnark` which represents our backend and of mapping ACIR into an R1CS-friendly data structure. Even though gnark supports several proving systems (like Plonk and Groth16) this wrapper will translate ACIR into R1CS. In the future, more proving systems can be easily supported (we are already planning on supporting Plonk. By this I mean that, a C++ Plonk implementation is already supported as a backend for Noir, but gnark's Plonk implementation isn't).

The first part is not so difficult. We just followed the other Noir backends' structure (see [Arkwork's Marlin's](https://github.com/noir-lang/marlin_arkworks_backend/tree/master/src) and [Aztec's Plonk's](https://github.com/noir-lang/aztec_backend/tree/master/barretenberg_static_lib/src)).

The second part takes most of the work. It can be cut into two parts: the raw R1CS generation (ACIR translation) and the communication with the concrete backend (glue between Rust and Go). In the following paragraphs, we are going to explain these sub-parts a little bit better.

Generating a raw R1CS or translating ACIR to something R1CS-friendly could be seen as just mapping a struct to another struct. For this, we've made two structs: `RawR1CS` and `RawGate`.

The communication between the concrete backend (the one written in Go) could be done through a pre-compiled WASM API or through FFI. For this, what we are basically doing is serializing the `RawR1CS` struct into JSON and sending it as a parameter for the WASM functions (in the case that we end up using the WASM API) or to the Go functions (FFI). At the moment we are looking for the easiest way to communicate Rust with Go. We started using WASMER but it is a little bit limited in terms of the amount of information that can be sent to a WASM function so we have discarded it for the moment (a second look could help here). Another step can be to try another WASM library called WASM-PACK, but we decided to start researching FFI.

And that's it for this module, in the next section we are going to dive a little deeper into the WASM API.

### Concrete backend

This module is the real deal. It is in charge of generating the proof for a given circuit and also of verifying a given proof. Using the raw R1CS received from the backend wrapper, it rebuilds the circuit and generates the proof or verifies a proof (depending on what function you are using).

The API would compile to WASM which is going to be used by the Rust wrapper. Or it would just expose functions for the Rust FFI (again, we are researching which is the easiest way to interface).


## Modules

### gnark_backend_ffi/

Written in Go and using gnark, this modules contains the concrete backend implementation.

#### `acir/`

Noir code compiles to an intermediate representation specific for arithmetic circuits called abstract circuit intermediate representation (ACIR), hence the name of this module. The compiled circuit is sent through Rust to the Go backend using a Foreign Function Interface (FFI). We encode Rust's types into C strings and send them to Go where they are decoded.

On the Go side, this module defines the same structures that comprise a compiled circuit (a.k.a. an ACIR instance) and the way they are serialized. Inside the module, we can find the two submodules (`opcode` and `term`) and the code for the `ACIR` struct (in `acir.go`). The `ACIR` struct is defined as follows:

```go
type ACIR struct {
	CurrentWitness common.Witness
	Opcodes        []opcode.Opcode
	PublicInputs   common.Witnesses
}
```

- `CurrentWitness` keeps the track of the number of witnesses that the circuit has. In this context, a witness could be either a public or a secret variable (also secret variables are the private ones).
- `Opcodes` is an array that contains the different ACIR opcodes which could be Arithmetic opcodes that represent a constraint to be enforced, Black Box Function opcodes which are more complex arithmetic opcodes that imply the use of gadgets, and Directive opcodes which are optimizations made and used in the Rust backend side (they don't need to be handled in the Go side). 
- `PublicInputs`

#### `opcode/` 

Above we explain what opcodes and below we dive deep into their structures. Among them we could find:

`ArithmeticOpcode`s, which, defined as
```go
type ArithmeticOpcode struct {
	MulTerms    term.MulTerms
	SimpleTerms term.SimpleTerms
	QC          fr_bn254.Element
}
```
is a struct that represents a Plonk constraint ($q_{L} \cdot x_{a} + q_{R} \cdot x_{b} 
 q_{O} \cdot x_{c} + q_{M} \cdot (x_{a} \cdot x_{b}) + q_{C} = 0$). `MulTerms` is a vector that represents the following sum: $q_{M_1} \cdot (w_{L_{1}} * w_{R_1}) + \dots + q_{M_n} \cdot (w_{L_{n}} * w_{R_n})$, but right now we are assuming that only one term comes in the vector. `SimpleTerms` is a vector that could represent one term ($q_{O} \cdot x_{c}$), two terms ($q_{L} \cdot x_{a} + q_{R} \cdot x_{b}$) or three terms ($q_{L} \cdot x_{a} + q_{R} \cdot x_{b} + q_{O} \cdot x_{c}$). And finally `QC` represents the constant term ($q_{C}$).

`BlackBoxFunctionOpcode`s: This opcodes represent what it's called gadgets. Gadgets are essentially libraries that give you access to common types and operations when defining circuits. In this case gadgets refer to operations and not common types, such as function calls to Pedersen, Poseidon, SHA3, etc. We do not support this kind of opcodes currently.

`DirectiveOpcode`s which, given that we do not need to handle them in the Go side but it comes with the ACIR anyways, is an empty struct.

#### `term/`

This module contains the representation and serialization of the multiplication and non-multiplication terms in the Plonk constraint. These are the `MulTerm`, defined as

```go
// qM * (xa * xb)
type MulTerm struct {
	Coefficient       fr_bn254.Element
	MultiplicandIndex common.Witness
	MultiplierIndex   common.Witness
}
```

where `Coefficient` is $q_{M}$, `Multiplicand` is the index of $x_{a}$ in the values vector (or the public inputs vector) and `Multiplier` is the index of `x_{b}` in hte values vector (or the public inputs vector) of the Plonk's constraint.

and the `SimpleTerm` defined as

```go
// qL * xa or qR * xb or qC * xc
type SimpleTerm struct {
	Coefficient   fr_bn254.Element
	VariableIndex common.Witness
}
```

where `Coefficient` is $q_{L/R/C}$ and `VariableIndex` is the index of $xa/xb/xc$ in the values vector (or the public inputs vector). 

### `backend/`

The different backend implementations are located in this module. These are `plonk/` and `groth16/` (WIP). Every backend defines the basic API needed by Noir to compile, execute, prove and verify.

It is designed in such way that it should be easy to implement a new backend.

### `internal/`

As the name hits, this module is internal and it is not intended to be exposed for the common user. At the moment it contains mainly helper functions that could be serialization, deserialization and sampling functions.

### Rust

#### `acvm/`

This module does not contain logic. It's main purpose is to facilitate the namespace in the backend wrapper code to help the reader to differentiate where the types are from.

#### `gnark_backend_wrapper/`

Acting as a glue between Rust and Go, using `std::ffi`, in this module you can find the Go's backend mirror. By this I mean Rust functions that call Go functions. Similar to the Go's `backend/` module, this module is designed in such way that it should be easy to implement a new backend. For that, you just need to add a directory with the name of the proving system and implement the pertinent methods

#### `backend.rs`

As [said](###Backend-wrapper-written-in-Rust) in the overview, the structure that represents your backend must implement the trait `Backend`. You can find its implementation in this module. In order for the project to be able to implement more than one gnark backends, the implemented methods call to the wrapper API so you could have multiple implementations of the same method but referring to different backends. You could change the used backend easily using the Rust feature flags.
