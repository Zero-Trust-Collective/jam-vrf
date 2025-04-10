use crate::errors::{wrap_serialization_error, CryptoError};
use ark_serialize::CanonicalDeserialize;
use ark_vrf::{reexports::ark_serialize, suites::bandersnatch};
use bandersnatch::{AffinePoint, Output};
use pyo3::prelude::*;
use pyo3::types::PyBytes;

/// VRF output type common to both ietf and ring VRFs
///
/// **Args:**
/// - bytes: `bytes` - output bytes
///
/// **Raises:**
/// - `Exception` if an internal error is encountered
///
/// **Example:**
/**```
from jam_vrf import VRFOutput

# construct vrf output from a safrole ticket signature
signature = bytes.fromhex("1dfb...")
vrf_output = VRFOutput(signature[:32])
```*/
#[pyclass]
pub struct VRFOutput(pub Output);

#[pymethods]
impl VRFOutput {
    #[new]
    pub fn new(bytes: &[u8]) -> Result<Self, CryptoError> {
        let affine =
            AffinePoint::deserialize_compressed(&bytes[..]).map_err(wrap_serialization_error)?;
        Ok(Self(Output::from(affine)))
    }

    /// Return the VRF output hash
    ///
    /// **Example:**
    /**
    vrf_output: VRFOutput
    id = vrf_output.hash()[:32] # ticket IDs in JAM only use the first 32 bytes
    */
    fn hash<'py>(&self, py: Python<'py>) -> Py<PyBytes> {
        PyBytes::new(py, &self.0.hash()).into()
    }
}
