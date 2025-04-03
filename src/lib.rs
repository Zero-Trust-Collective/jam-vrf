use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, SerializationError};
use ark_vrf::{
    ietf::Verifier as IetfVerifier,
    reexports::ark_serialize,
    ring::{RingCommitment, Verifier as RingVerifier},
    suites::bandersnatch,
    Error as VrfError,
};
use bandersnatch::{
    AffinePoint, BandersnatchSha512Ell2, IetfProof, Input, Output, Public, RingProof,
    RingProofParams, RingVerifier as BandersnatchRingVerifier,
};
use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use srs::get_pcs_params;

mod srs;
#[cfg(test)]
mod tests;

/// Wrapper for VrfError to satisfy orphan rules
#[derive(Debug)]
pub struct VrfErrorWrapper(VrfError);

/// Wrapper for SerializationError to satisfy orphan rules
#[derive(Debug)]
pub struct SerializationErrorWrapper(SerializationError);

/// Custom error type
#[derive(Debug)]
pub enum CryptoError {
    VrfError(VrfErrorWrapper),
    SerializationError(SerializationErrorWrapper),
    InvalidInput(String),
}

fn wrap_vrf_error(err: VrfError) -> CryptoError {
    CryptoError::VrfError(VrfErrorWrapper(err))
}

fn wrap_serialization_error(err: SerializationError) -> CryptoError {
    CryptoError::SerializationError(SerializationErrorWrapper(err))
}

impl From<CryptoError> for PyErr {
    fn from(err: CryptoError) -> PyErr {
        match err {
            CryptoError::VrfError(VrfErrorWrapper(VrfError::VerificationFailure)) => {
                PyValueError::new_err("VRF verification failed")
            }
            CryptoError::VrfError(VrfErrorWrapper(VrfError::InvalidData)) => {
                PyValueError::new_err("Invalid VRF data")
            }
            CryptoError::SerializationError(SerializationErrorWrapper(
                SerializationError::NotEnoughSpace,
            )) => PyValueError::new_err("Not enough space for serialization"),
            CryptoError::SerializationError(SerializationErrorWrapper(
                SerializationError::InvalidData,
            )) => PyValueError::new_err("Invalid serialized data format"),
            CryptoError::SerializationError(SerializationErrorWrapper(
                SerializationError::UnexpectedFlags,
            )) => PyRuntimeError::new_err("Unknown serialization error"),
            CryptoError::SerializationError(SerializationErrorWrapper(
                SerializationError::IoError(_),
            )) => PyRuntimeError::new_err("IO error during serialization"),
            CryptoError::InvalidInput(data) => PyValueError::new_err(data),
        }
    }
}

/// Create a commitment from a list of public keys
#[pyfunction]
fn get_ring_commitment(py: Python<'_>, public_keys: Vec<Vec<u8>>) -> PyResult<Py<PyBytes>> {
    if public_keys.is_empty() {
        return Err(PyValueError::new_err("Public keys list cannot be empty"));
    }

    let pc_params = get_pcs_params();

    let params = RingProofParams::from_pcs_params(public_keys.len(), pc_params)
        .map_err(|e| PyValueError::new_err(format!("unable to initialize ring params: {:?}", e)))?;

    let parsed_keys: Vec<AffinePoint> = public_keys
        .iter()
        .map(|pk| {
            AffinePoint::deserialize_compressed(&pk[..]).unwrap_or(RingProofParams::padding_point())
        })
        .collect();

    let verifier_key = params.verifier_key(&parsed_keys);
    let commitment = verifier_key.commitment();

    let mut bytes = Vec::new();
    commitment
        .serialize_compressed(&mut bytes)
        .map_err(|e| PyValueError::new_err(format!("Failed to serialize commitment: {}", e)))?;

    Ok(PyBytes::new(py, &bytes).into())
}

/// VRF output type shared between single and ring VRF implementations
#[pyclass]
pub struct VRFOutput {
    output: Output,
}

#[pymethods]
impl VRFOutput {
    #[new]
    fn new(bytes: &[u8]) -> Result<Self, CryptoError> {
        let affine =
            AffinePoint::deserialize_compressed(&bytes[..]).map_err(wrap_serialization_error)?;
        Ok(Self {
            output: Output::from(affine),
        })
    }

    /// Get the serialized bytes
    fn bytes<'py>(&self, py: Python<'py>) -> Result<Py<PyBytes>, CryptoError> {
        let mut bytes = Vec::new();
        self.output
            .serialize_compressed(&mut bytes)
            .map_err(wrap_serialization_error)?;
        Ok(PyBytes::new(py, &bytes).into())
    }

    /// Get the hash bytes
    fn hash<'py>(&self, py: Python<'py>) -> Py<PyBytes> {
        PyBytes::new(py, &self.output.hash()).into()
    }
}

/// VRF proof for single signatures
#[pyclass]
pub struct SingleVRFProof {
    proof: IetfProof,
}

#[pymethods]
impl SingleVRFProof {
    #[new]
    fn new(bytes: &[u8]) -> Result<Self, CryptoError> {
        let proof =
            IetfProof::deserialize_compressed(&bytes[..]).map_err(wrap_serialization_error)?;
        Ok(Self { proof })
    }

    /// Get the serialized bytes
    fn bytes<'py>(&self, py: Python<'py>) -> Result<Py<PyBytes>, CryptoError> {
        let mut bytes = Vec::new();
        self.proof
            .serialize_compressed(&mut bytes)
            .map_err(wrap_serialization_error)?;
        Ok(PyBytes::new(py, &bytes).into())
    }
}

/// VRF proof for ring signatures
#[pyclass]
pub struct RingVRFProof {
    proof: RingProof,
}

#[pymethods]
impl RingVRFProof {
    #[new]
    fn new(bytes: &[u8]) -> Result<Self, CryptoError> {
        let proof =
            RingProof::deserialize_compressed(&bytes[..]).map_err(wrap_serialization_error)?;
        Ok(Self { proof })
    }

    /// Get the serialized bytes
    fn bytes<'py>(&self, py: Python<'py>) -> Result<Py<PyBytes>, CryptoError> {
        let mut bytes = Vec::new();
        self.proof
            .serialize_compressed(&mut bytes)
            .map_err(wrap_serialization_error)?;
        Ok(PyBytes::new(py, &bytes).into())
    }
}

/// VRF verifier for single signatures
#[pyclass]
pub struct SingleVRFVerifier;

#[pymethods]
impl SingleVRFVerifier {
    #[new]
    fn new() -> Self {
        Self
    }

    /// Verify a VRF proof and output for a data using a public key
    fn verify(
        &self,
        public_key: &[u8],
        data: &[u8],
        ad: &[u8],
        output: &VRFOutput,
        proof: &SingleVRFProof,
    ) -> Result<(), CryptoError> {
        let public =
            Public::deserialize_compressed(&public_key[..]).map_err(wrap_serialization_error)?;
        let input = Input::new(data).ok_or(CryptoError::InvalidInput(
            "Failed to create VRF input from data".to_string(),
        ))?;
        IetfVerifier::verify(&public, input, output.output, ad, &proof.proof)
            .map_err(wrap_vrf_error)
    }
}

/// VRF verifier for ring signatures
#[pyclass]
pub struct RingVRFVerifier {
    verifier: BandersnatchRingVerifier,
}

#[pymethods]
impl RingVRFVerifier {
    /// Create a new RingVRFVerifier instance from a commitment
    #[new]
    fn new(commitment: &[u8], ring_size: usize) -> Result<Self, CryptoError> {
        let commitment =
            <RingCommitment<BandersnatchSha512Ell2>>::deserialize_compressed(&commitment[..])
                .map_err(wrap_serialization_error)?;

        let pc_params = get_pcs_params();

        let params = RingProofParams::from_pcs_params(ring_size, pc_params).map_err(|e| {
            CryptoError::InvalidInput(format!("unable to initialize ring params: {:?}", e))
        })?;

        let verifier_key = params.verifier_key_from_commitment(commitment);
        let verifier = params.verifier(verifier_key);

        Ok(Self { verifier })
    }

    /// Verify a ring VRF proof and output
    fn verify(
        &self,
        data: &[u8],
        ad: &[u8],
        output: &VRFOutput,
        proof: &RingVRFProof,
    ) -> Result<(), CryptoError> {
        let input = Input::new(data).ok_or_else(|| {
            CryptoError::InvalidInput("Failed to create VRF input from data".to_string())
        })?;

        <Public as RingVerifier<BandersnatchSha512Ell2>>::verify(
            input,
            output.output,
            ad,
            &proof.proof,
            &self.verifier,
        )
        .map_err(wrap_vrf_error)
    }
}

/// Python module
#[pymodule]
fn pyvrfs(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<VRFOutput>()?;
    m.add_class::<SingleVRFProof>()?;
    m.add_class::<RingVRFProof>()?;
    m.add_class::<SingleVRFVerifier>()?;
    m.add_class::<RingVRFVerifier>()?;
    m.add_function(wrap_pyfunction!(get_ring_commitment, m)?)?;
    Ok(())
}
