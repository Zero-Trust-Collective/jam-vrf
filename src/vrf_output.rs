use crate::errors::{wrap_serialization_error, CryptoError};
use ark_serialize::CanonicalDeserialize;
use ark_vrf::{reexports::ark_serialize, suites::bandersnatch};
use bandersnatch::{AffinePoint, Output};
use pyo3::prelude::*;
use pyo3::types::PyBytes;

/// VRF output type common to both ietf and ring VRFs
///
/// **Args:**
/// - output: `bytes`
///
/// **Raises:**
/// - `Exception` - internal error
///
/// **Example:** `vrf_output = VRFOutput(output)`
#[pyclass]
pub struct VRFOutput(pub Output);

#[pymethods]
impl VRFOutput {
    #[new]
    pub fn new(output: &[u8]) -> Result<Self, CryptoError> {
        let affine =
            AffinePoint::deserialize_compressed(&output[..]).map_err(wrap_serialization_error)?;
        Ok(Self(Output::from(affine)))
    }

    /// Hash the VRF output point
    ///
    /// **Example:** `id = VRFOutput(...).hash()`
    fn hash<'py>(&self, py: Python<'py>) -> Py<PyBytes> {
        PyBytes::new(py, &self.0.hash()).into()
    }
}
