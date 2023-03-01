use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use noir_backend_using_gnark::{acvm, gnark_backend_wrapper};
use serde_json::json;
use std::ffi;

extern "C" {
    fn TestFeltSerialization(felt: gnark_backend_wrapper::groth16::GoString) -> *const ffi::c_char;
    fn TestFeltsSerialization(
        felts: gnark_backend_wrapper::groth16::GoString,
    ) -> *const ffi::c_char;
    fn TestU64Serialization(unsigned_integer: ffi::c_ulong) -> ffi::c_ulong;
    fn TestMulTermSerialization(
        mul_term: gnark_backend_wrapper::groth16::GoString,
    ) -> *const ffi::c_char;
    fn TestMulTermsSerialization(
        mul_terms: gnark_backend_wrapper::groth16::GoString,
    ) -> *const ffi::c_char;
    fn TestAddTermSerialization(
        add_term: gnark_backend_wrapper::groth16::GoString,
    ) -> *const ffi::c_char;
    fn TestAddTermsSerialization(
        add_terms: gnark_backend_wrapper::groth16::GoString,
    ) -> *const ffi::c_char;
    fn TestRawGateSerialization(
        raw_gate: gnark_backend_wrapper::groth16::GoString,
    ) -> *const ffi::c_char;
    fn TestRawGatesSerialization(
        raw_gates: gnark_backend_wrapper::groth16::GoString,
    ) -> *const ffi::c_char;
    fn TestRawR1CSSerialization(
        raw_r1cs: gnark_backend_wrapper::groth16::GoString,
    ) -> *const ffi::c_char;
}

fn serialize_felt(felt: &gnark_backend_wrapper::groth16::Fr) -> Vec<u8> {
    let mut serialized_felt = Vec::new();
    felt.serialize_uncompressed(&mut serialized_felt).unwrap();
    // Turn little-endian to big-endian.
    serialized_felt.reverse();
    serialized_felt
}

fn deserialize_felt(felt_bytes: &[u8]) -> gnark_backend_wrapper::groth16::Fr {
    let mut decoded = hex::decode(felt_bytes).unwrap();
    // Turn big-endian to little-endian.
    decoded.reverse();
    gnark_backend_wrapper::groth16::Fr::deserialize_uncompressed(decoded.as_slice()).unwrap()
}

// This serialization mimics gnark's serialization of a field elements vector.
// The length of the vector is encoded as a u32 on the first 4 bytes.
fn serialize_felts(felts: &[gnark_backend_wrapper::groth16::Fr]) -> Vec<u8> {
    let mut buff: Vec<u8> = Vec::new();
    let n_felts: u32 = felts.len().try_into().unwrap();
    buff.extend_from_slice(&n_felts.to_be_bytes());
    buff.extend_from_slice(&felts.iter().flat_map(serialize_felt).collect::<Vec<u8>>());
    buff
}

#[test]
fn test_felt_serialization() {
    // Sample a random felt.
    let felt: gnark_backend_wrapper::groth16::Fr = rand::random();

    println!("| RUST |\n{:?}", felt.0 .0);

    // Serialize the random felt.
    let serialized_felt = serialize_felt(&felt);

    // Encode the felt.
    let encoded_felt = hex::encode(serialized_felt);

    // Prepare ping for Go.
    let pre_ping = ffi::CString::new(encoded_felt).unwrap();
    let ping = gnark_backend_wrapper::groth16::GoString::try_from(&pre_ping).unwrap();

    // Send and receive pong from Go.
    let pong: *const ffi::c_char = unsafe { TestFeltSerialization(ping) };

    // Prepare pong for Rust.
    let go_pre_serialized_felt = unsafe { ffi::CStr::from_ptr(pong) };
    let go_serialized_felt = go_pre_serialized_felt.to_str().unwrap().as_bytes();

    let go_felt = deserialize_felt(go_serialized_felt);

    assert_eq!(felt, go_felt)
}

#[test]
fn test_felts_serialization() {
    // Sample a random felt.
    let felts: [gnark_backend_wrapper::groth16::Fr; 2] = rand::random();

    println!(
        "| RUST |\n{:?}",
        felts.iter().map(|felt| felt.0 .0).collect::<Vec<_>>()
    );

    // Serialize the random felts and pack them into one byte array.
    let serialized_felts = serialize_felts(&felts);

    // Encode the packed felts.
    let encoded_felts = hex::encode(serialized_felts);

    // Prepare ping for Go.
    let pre_ping = ffi::CString::new(encoded_felts).unwrap();
    let ping = gnark_backend_wrapper::groth16::GoString::try_from(&pre_ping).unwrap();

    // Send and receive pong from Go.
    let pong: *const ffi::c_char = unsafe { TestFeltsSerialization(ping) };

    // Prepare pong for Rust.
    let go_pre_serialized_felt = unsafe { ffi::CStr::from_ptr(pong) };
    let go_serialized_felt = go_pre_serialized_felt.to_str().unwrap().as_bytes();

    // Decode and deserialize the unpacked felts.
    let go_felts: Vec<gnark_backend_wrapper::groth16::Fr> = hex::decode(go_serialized_felt)
        .unwrap()[4..] // Skip the vector length corresponding to the first four bytes.
        .chunks_mut(32)
        .map(|go_decoded_felt| {
            // Turn big-endian to little-endian.
            go_decoded_felt.reverse();
            // Here I reference after dereference because I had a mutable reference and I need a non-mutable one.
            let felt: gnark_backend_wrapper::groth16::Fr =
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
    let pong = unsafe { TestU64Serialization(ping) };

    assert_eq!(number, pong)
}
