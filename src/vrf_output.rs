use crate::errors::{wrap_serialization_error, CryptoError};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_vrf::{reexports::ark_serialize, suites::bandersnatch};
use bandersnatch::{AffinePoint, Output};
use pyo3::prelude::*;
use pyo3::types::PyBytes;

/// VRF output type shared between single and ring VRF implementations
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

    /// Get the serialized bytes
    pub fn bytes<'py>(&self, py: Python<'py>) -> Result<Py<PyBytes>, CryptoError> {
        let mut bytes = Vec::new();
        self.output
            .serialize_compressed(&mut bytes)
            .map_err(wrap_serialization_error)?;
        Ok(PyBytes::new(py, &bytes).into())
    }

    /// Get the hash bytes
    pub fn hash<'py>(&self, py: Python<'py>) -> Py<PyBytes> {
        PyBytes::new(py, &self.output.hash()).into()
    }
}
