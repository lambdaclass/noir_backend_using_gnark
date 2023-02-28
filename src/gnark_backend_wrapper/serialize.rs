use super::acir_to_r1cs::{RawGate, RawR1CS};
use acvm::acir::native_types::Witness;
use serde::{ser::SerializeStruct, Serialize};

impl Serialize for RawR1CS {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut s = serializer.serialize_struct("RawR1CS", 4)?;

        let mut serializable_values: Vec<String> = Vec::new();
        for value in &self.values {
            let mut serialized_value = Vec::new();
            ark_serialize::CanonicalSerialize::serialize_uncompressed(value, &mut serialized_value)
                .map_err(|e| serde::ser::Error::custom(e.to_string()))?;
            serializable_values.push(hex::encode(serialized_value));
        }

        s.serialize_field("gates", &self.gates)?;
        s.serialize_field("public_inputs", &self.public_inputs)?;
        s.serialize_field("values", &serializable_values)?;
        s.serialize_field("num_variables", &self.num_variables)?;
        s.end()
    }
}

impl Serialize for RawGate {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut s = serializer.serialize_struct("RawGate", 3)?;

        let mut serializable_mul_terms: Vec<(String, Witness, Witness)> = Vec::new();
        for (coefficient, multiplier, multiplicand) in &self.mul_terms {
            let mut serialized_coefficient = Vec::new();
            ark_serialize::CanonicalSerialize::serialize_uncompressed(
                coefficient,
                &mut serialized_coefficient,
            )
            .map_err(|e| serde::ser::Error::custom(e.to_string()))?;
            serializable_mul_terms.push((
                hex::encode(serialized_coefficient),
                *multiplicand,
                *multiplier,
            ));
        }

        let mut serializable_add_terms: Vec<(String, Witness)> = Vec::new();
        for (coefficient, sum) in &self.add_terms {
            let mut serialized_coefficient = Vec::new();
            ark_serialize::CanonicalSerialize::serialize_uncompressed(
                coefficient,
                &mut serialized_coefficient,
            )
            .map_err(|e| serde::ser::Error::custom(e.to_string()))?;
            serializable_add_terms.push((hex::encode(serialized_coefficient), *sum));
        }

        let mut serializable_constant_term = Vec::new();
        ark_serialize::CanonicalSerialize::serialize_uncompressed(
            &self.constant_term,
            &mut serializable_constant_term,
        )
        .map_err(|e| serde::ser::Error::custom(e.to_string()))?;

        s.serialize_field("mul_terms", &serializable_add_terms)?;
        s.serialize_field("add_terms", &serializable_add_terms)?;
        s.serialize_field("constant_term", &hex::encode(serializable_constant_term))?;
        s.end()
    }
}
