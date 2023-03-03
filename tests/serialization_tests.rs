#![allow(clippy::uninlined_format_args)]

use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use noir_backend_using_gnark::{
    acvm,
    gnark_backend_wrapper::{self, AddTerm, MulTerm, RawGate, RawR1CS},
};
use std::ffi;

extern "C" {
    fn IntegrationTestFeltSerialization(
        felt: gnark_backend_wrapper::GoString,
    ) -> *const ffi::c_char;
    fn IntegrationTestFeltsSerialization(
        felts: gnark_backend_wrapper::GoString,
    ) -> *const ffi::c_char;
    fn IntegrationTestU64Serialization(unsigned_integer: ffi::c_ulong) -> ffi::c_ulong;
    fn IntegrationTestMulTermSerialization(
        mul_term: gnark_backend_wrapper::GoString,
    ) -> *const ffi::c_char;
    fn IntegrationTestMulTermsSerialization(
        mul_terms: gnark_backend_wrapper::GoString,
    ) -> *const ffi::c_char;
    fn IntegrationTestAddTermSerialization(
        add_term: gnark_backend_wrapper::GoString,
    ) -> *const ffi::c_char;
    fn IntegrationTestAddTermsSerialization(
        add_terms: gnark_backend_wrapper::GoString,
    ) -> *const ffi::c_char;
    fn IntegrationTestRawGateSerialization(
        raw_gate: gnark_backend_wrapper::GoString,
    ) -> *const ffi::c_char;
    fn IntegrationTestRawGatesSerialization(
        raw_gates: gnark_backend_wrapper::GoString,
    ) -> *const ffi::c_char;
    fn IntegrationTestRawR1CSSerialization(
        raw_r1cs: gnark_backend_wrapper::GoString,
    ) -> *const ffi::c_char;
}

fn serialize_felt(felt: &gnark_backend_wrapper::Fr) -> Vec<u8> {
    let mut serialized_felt = Vec::new();
    felt.serialize_uncompressed(&mut serialized_felt).unwrap();
    // Turn little-endian to big-endian.
    serialized_felt.reverse();
    serialized_felt
}

fn deserialize_felt(felt_bytes: &[u8]) -> gnark_backend_wrapper::Fr {
    let mut decoded = hex::decode(felt_bytes).unwrap();
    // Turn big-endian to little-endian.
    decoded.reverse();
    gnark_backend_wrapper::Fr::deserialize_uncompressed(decoded.as_slice()).unwrap()
}

// This serialization mimics gnark's serialization of a field elements vector.
// The length of the vector is encoded as a u32 on the first 4 bytes.
fn serialize_felts(felts: &[gnark_backend_wrapper::Fr]) -> Vec<u8> {
    let mut buff: Vec<u8> = Vec::new();
    let n_felts: u32 = felts.len().try_into().unwrap();
    buff.extend_from_slice(&n_felts.to_be_bytes());
    buff.extend_from_slice(&felts.iter().flat_map(serialize_felt).collect::<Vec<u8>>());
    buff
}

fn ping_pong(
    encoded_element: String,
    go_function: unsafe extern "C" fn(gnark_backend_wrapper::GoString) -> *const ffi::c_char,
) -> &'static [u8] {
    // Prepare ping for Go.
    let pre_ping = ffi::CString::new(encoded_element).unwrap();
    let ping = gnark_backend_wrapper::GoString::try_from(&pre_ping).unwrap();

    // Send and receive pong from Go.
    let pong: *const ffi::c_char = unsafe { go_function(ping) };

    // Prepare pong for Rust.
    let go_pre_serialized_element = unsafe { ffi::CStr::from_ptr(pong) };

    go_pre_serialized_element.to_str().unwrap().as_bytes()
}

fn random_add_term() -> AddTerm {
    // Sample random coefficient.
    let coefficient: gnark_backend_wrapper::Fr = rand::random();
    // Sample a random sum.
    let sum = acvm::Witness::new(rand::random());
    AddTerm { coefficient, sum }
}

#[test]
fn test_felt_serialization() {
    // Sample a random felt.
    let felt: gnark_backend_wrapper::Fr = rand::random();

    println!("| RUST |\n{:?}", felt.0 .0);

    // Serialize the random felt.
    let serialized_felt = serialize_felt(&felt);

    // Encode the felt.
    let encoded_felt = hex::encode(serialized_felt);

    let go_serialized_felt = ping_pong(encoded_felt, IntegrationTestFeltSerialization);

    let go_felt = deserialize_felt(go_serialized_felt);

    assert_eq!(felt, go_felt)
}

#[test]
fn test_felts_serialization() {
    // Sample a random felt.
    let felts: [gnark_backend_wrapper::Fr; 2] = rand::random();

    println!(
        "| RUST |\n{:?}",
        felts.iter().map(|felt| felt.0 .0).collect::<Vec<_>>()
    );

    // Serialize the random felts and pack them into one byte array.
    let serialized_felts = serialize_felts(&felts);

    // Encode the felts.
    let encoded_felts = hex::encode(serialized_felts);

    let go_serialized_felt = ping_pong(encoded_felts, IntegrationTestFeltsSerialization);

    // Decode and deserialize the unpacked felts.
    let go_felts: Vec<gnark_backend_wrapper::Fr> = hex::decode(go_serialized_felt).unwrap()[4..] // Skip the vector length corresponding to the first four bytes.
        .chunks_mut(32)
        .map(|go_decoded_felt| {
            // Turn big-endian to little-endian.
            go_decoded_felt.reverse();
            // Here I reference after dereference because I had a mutable reference and I need a non-mutable one.
            let felt: gnark_backend_wrapper::Fr =
                CanonicalDeserialize::deserialize_uncompressed(&*go_decoded_felt).unwrap();
            felt
        })
        .collect();

    assert_eq!(felts.to_vec(), go_felts)
}

#[test]
fn test_u64_serialization() {
    // Sample a random number.
    let number: u64 = rand::random();

    println!("| RUST |\n{:?}", number);

    // Prepare ping for Go.
    let ping = number;
    // Send and receive pong from Go.
    let pong = unsafe { IntegrationTestU64Serialization(ping) };

    assert_eq!(number, pong)
}

#[test]
fn test_mul_term_serialization() {
    // Sample random coefficient.
    let coefficient: gnark_backend_wrapper::Fr = rand::random();
    // Sample a random multiplicand.
    let multiplicand = acvm::Witness::new(rand::random());
    // Sample a random multiplier.
    let multiplier: acvm::Witness = acvm::Witness::new(rand::random());
    // Sample a random mul term.
    let mul_term = MulTerm {
        coefficient,
        multiplicand,
        multiplier,
    };

    println!("| RUST |");
    println!("{mul_term:?}");

    // Serialize the mul term.
    let serialized_mul_term = serde_json::to_string(&mul_term).unwrap();

    let _go_serialized_mul_term =
        ping_pong(serialized_mul_term, IntegrationTestMulTermSerialization);
    // TODO:
    // * Prepare pong for Rust.
    // * Assert that mul_term and go_mul_term are the same (go_mul_term is
    //   the pong's deserialization)
}

#[test]
fn test_mul_terms_serialization() {
    // Sample random coefficient.
    let coefficient: gnark_backend_wrapper::Fr = rand::random();
    // Sample a random multiplicand.
    let multiplicand = acvm::Witness::new(rand::random());
    // Sample a random multiplier.
    let multiplier: acvm::Witness = acvm::Witness::new(rand::random());
    // Sample a random mul term.
    let mul_terms = vec![
        MulTerm {
            coefficient,
            multiplicand,
            multiplier,
        },
        MulTerm {
            coefficient,
            multiplicand,
            multiplier,
        },
    ];

    println!("| RUST |");
    println!("{mul_terms:?}");

    // Serialize the mul term.
    let serialized_mul_terms = serde_json::to_string(&mul_terms).unwrap();

    let _go_serialized_mul_terms =
        ping_pong(serialized_mul_terms, IntegrationTestMulTermsSerialization);
    // TODO:
    // * Prepare pong for Rust.
    // * Assert that mul_term and go_mul_term are the same (go_mul_term is
    //   the pong's deserialization)
}

#[test]
fn test_add_term_serialization() {
    // Sample a random add term.
    let add_term = random_add_term();

    println!("| RUST |");
    println!("{add_term:?}");

    // Serialize the mul term.
    let serialized_add_term = serde_json::to_string(&add_term).unwrap();

    let _go_serialized_add_term =
        ping_pong(serialized_add_term, IntegrationTestAddTermSerialization);

    // TODO:
    // * Prepare pong for Rust.
    // * Assert that add_term and go_add_term are the same (go_add_term is
    //   the pong's deserialization)
}

#[test]
fn test_add_terms_serialization() {
    // Sample random coefficient.
    let coefficient: gnark_backend_wrapper::Fr = rand::random();
    // Sample a random sum.
    let sum = acvm::Witness::new(rand::random());
    // Sample a random mul term.
    let add_terms = vec![AddTerm { coefficient, sum }, AddTerm { coefficient, sum }];

    println!("| RUST |");
    println!("{add_terms:?}");

    // Serialize the mul term.
    let serialized_add_terms = serde_json::to_string(&add_terms).unwrap();

    let _go_serialized_add_terms =
        ping_pong(serialized_add_terms, IntegrationTestAddTermsSerialization);

    // TODO:
    // * Prepare pong for Rust.
    // * Assert that add_terms and go_add_terms are the same (go_add_terms is
    //   the pong's deserialization)
}

#[test]
fn test_raw_gate_serialization() {
    let coefficient: gnark_backend_wrapper::Fr = rand::random();
    let multiplicand = acvm::Witness::new(rand::random());
    let multiplier: acvm::Witness = acvm::Witness::new(rand::random());
    let sum = acvm::Witness::new(rand::random());
    let add_term = AddTerm { coefficient, sum };
    let add_terms = vec![add_term, add_term];
    let mul_term = MulTerm {
        coefficient,
        multiplicand,
        multiplier,
    };
    let mul_terms = vec![mul_term, mul_term];
    let constant_term: gnark_backend_wrapper::Fr = rand::random();
    let raw_gate = RawGate {
        mul_terms,
        add_terms,
        constant_term,
    };

    println!("| RUST |");
    println!("{raw_gate:?}");

    // Serialize the raw gate.
    let serialized_raw_gate = serde_json::to_string(&raw_gate).unwrap();

    let _go_serialized_raw_gate =
        ping_pong(serialized_raw_gate, IntegrationTestRawGateSerialization);

    // TODO:
    // * Prepare pong for Rust.
    // * Assert that add_terms and go_add_terms are the same (go_add_terms is
    //   the pong's deserialization)
}

#[test]
fn test_raw_gates_serialization() {
    let coefficient: gnark_backend_wrapper::Fr = rand::random();
    let multiplicand = acvm::Witness::new(rand::random());
    let multiplier: acvm::Witness = acvm::Witness::new(rand::random());
    let sum = acvm::Witness::new(rand::random());
    let add_term = AddTerm { coefficient, sum };
    let add_terms = vec![add_term, add_term];
    let mul_term = MulTerm {
        coefficient,
        multiplicand,
        multiplier,
    };
    let mul_terms = vec![mul_term, mul_term];
    let constant_term: gnark_backend_wrapper::Fr = rand::random();
    let raw_gate = RawGate {
        mul_terms,
        add_terms,
        constant_term,
    };
    let raw_gates = vec![raw_gate.clone(), raw_gate];

    println!("| RUST |");
    println!("{raw_gates:?}");

    // Serialize the raw gate.
    let serialized_raw_gates = serde_json::to_string(&raw_gates).unwrap();

    let _go_serialized_raw_gates =
        ping_pong(serialized_raw_gates, IntegrationTestRawGatesSerialization);

    // TODO:
    // * Prepare pong for Rust.
    // * Assert that add_terms and go_add_terms are the same (go_add_terms is
    //   the pong's deserialization)
}

#[test]
fn test_raw_r1cs_serialization() {
    let coefficient: gnark_backend_wrapper::Fr = rand::random();
    let multiplicand = acvm::Witness::new(rand::random());
    let multiplier: acvm::Witness = acvm::Witness::new(rand::random());
    let sum = acvm::Witness::new(rand::random());
    let add_term = AddTerm { coefficient, sum };
    let add_terms = vec![add_term, add_term];
    let mul_term = MulTerm {
        coefficient,
        multiplicand,
        multiplier,
    };
    let mul_terms = vec![mul_term, mul_term];
    let constant_term: gnark_backend_wrapper::Fr = rand::random();
    let raw_gate = RawGate {
        mul_terms,
        add_terms,
        constant_term,
    };
    let raw_gates = vec![raw_gate.clone(), raw_gate];
    let public_inputs = vec![
        acvm::Witness::new(rand::random()),
        acvm::Witness::new(rand::random()),
    ];
    let values: [gnark_backend_wrapper::Fr; 2] = rand::random();
    let num_constraints: u64 = rand::random();
    let num_variables: u64 = rand::random();
    let raw_r1cs = RawR1CS {
        gates: raw_gates,
        public_inputs,
        values: values.to_vec(),
        num_variables,
        num_constraints,
    };

    println!("| RUST |");
    println!("{raw_r1cs:?}");

    // Serialize the raw r1cs.
    let serialized_raw_r1cs = serde_json::to_string(&raw_r1cs).unwrap();

    let _go_serialized_raw_r1cs =
        ping_pong(serialized_raw_r1cs, IntegrationTestRawR1CSSerialization);

    // TODO:
    // * Prepare pong for Rust.
    // * Assert that add_terms and go_add_terms are the same (go_add_terms is
    //   the pong's deserialization)
}
