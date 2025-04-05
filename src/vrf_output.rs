use crate::errors::{wrap_serialization_error, CryptoError};
use ark_serialize::CanonicalDeserialize;
use ark_vrf::{reexports::ark_serialize, suites::bandersnatch};
use bandersnatch::{AffinePoint, Output};
use pyo3::prelude::*;

/// VRF output type shared between ietf and ring VRF implementations
#[pyclass]
pub struct VRFOutput {
    pub output: Output,
}

#[pymethods]
impl VRFOutput {
    #[new]
    pub fn new(bytes: &[u8]) -> Result<Self, CryptoError> {
        let affine =
            AffinePoint::deserialize_compressed(&bytes[..]).map_err(wrap_serialization_error)?;
        Ok(Self {
            output: Output::from(affine),
        })
    }
}
