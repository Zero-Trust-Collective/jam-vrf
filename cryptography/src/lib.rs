use ark_ec_vrfs::{
    ietf::{Prover as IetfProver, Verifier as IetfVerifier},
    ring::{Prover as RingProver, Verifier as RingVerifier},
    prelude::ark_serialize,
    suites::bandersnatch::edwards as bandersnatch,
    suites::bandersnatch::edwards::RingContext,
    Error as VrfError,
};
use bandersnatch::{
    AffinePoint, BandersnatchSha512Ell2, IetfProof, Input, Output, Public, RingProof, Secret,
};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, SerializationError};
use pyo3::prelude::*;
use pyo3::exceptions::{PyValueError, PyRuntimeError};
use pyo3::types::PyBytes;

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

impl From<VrfErrorWrapper> for CryptoError {
    fn from(err: VrfErrorWrapper) -> Self {
        CryptoError::VrfError(err)
    }
}

fn wrap_vrf_error(err: VrfError) -> CryptoError {
    CryptoError::VrfError(VrfErrorWrapper(err))
}

impl From<SerializationErrorWrapper> for CryptoError {
    fn from(err: SerializationErrorWrapper) -> Self {
        CryptoError::SerializationError(err)
    }
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
            CryptoError::SerializationError(SerializationErrorWrapper(SerializationError::NotEnoughSpace)) => {
                PyValueError::new_err("Not enough space for serialization")
            }
            CryptoError::SerializationError(SerializationErrorWrapper(SerializationError::InvalidData)) => {
                PyValueError::new_err("Invalid serialized data format")
            }
            CryptoError::SerializationError(SerializationErrorWrapper(SerializationError::UnexpectedFlags)) => {
                PyRuntimeError::new_err("Unknown serialization error")
            }
            CryptoError::SerializationError(SerializationErrorWrapper(SerializationError::IoError(_))) => {
                PyRuntimeError::new_err("IO error during serialization")
            }
            CryptoError::InvalidInput(data) => PyValueError::new_err(data),
        }
    }
}

/// Get RingContext with proper SRS parameters
fn get_ring_context(ring_size: usize) -> Result<RingContext, CryptoError> {
    let pcs_params = srs::get_pcs_params();
    RingContext::from_srs(ring_size, pcs_params)
        .map_err(|_| CryptoError::InvalidInput("Failed to create ring context".to_string()))
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
        let affine = AffinePoint::deserialize_compressed(&mut &bytes[..])
            .map_err(wrap_serialization_error)?;
        Ok(Self {
            output: Output::from(affine)
        })
    }

    /// Get the serialized bytes
    fn bytes<'py>(&self, py: Python<'py>) -> Result<Py<PyBytes>, CryptoError> {
        let mut bytes = Vec::new();
        self.output.serialize_uncompressed(&mut bytes)
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
    /// Get the serialized bytes
    fn bytes<'py>(&self, py: Python<'py>) -> Result<Py<PyBytes>, CryptoError> {
        let mut bytes = Vec::new();
        self.proof.serialize_uncompressed(&mut bytes)
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
    /// Get the serialized bytes
    fn bytes<'py>(&self, py: Python<'py>) -> Result<Py<PyBytes>, CryptoError> {
        let mut bytes = Vec::new();
        self.proof.serialize_uncompressed(&mut bytes)
            .map_err(wrap_serialization_error)?;
        Ok(PyBytes::new(py, &bytes).into())
    }
}

/// VRF key pair for both single and ring signatures
#[pyclass]
pub struct KeyPairVRF {
    secret: Secret,
}

#[pymethods]
impl KeyPairVRF {
    #[new]
    fn new() -> Self {
        let mut rng: ark_std::rand::prelude::ThreadRng = ark_std::rand::thread_rng();
        let secret = Secret::from_rand(&mut rng);
        Self { secret }
    }

    /// Get the serialized public key
    fn public_key_bytes<'py>(&self, py: Python<'py>) -> Result<Py<PyBytes>, CryptoError> {
        let mut bytes = Vec::new();
        self.secret.public.0.serialize_compressed(&mut bytes)
            .map_err(wrap_serialization_error)?;
        Ok(PyBytes::new(py, &bytes).into())
    }
}

/// VRF operations for single signatures
#[pyclass]
pub struct SingleVRF;

#[pymethods]
impl SingleVRF {
    #[new]
    fn new() -> Self {
        Self
    }

    /// Generate VRF proof and output for a data using a key pair
    #[staticmethod]
    fn prove(key_pair: &KeyPairVRF, data: &[u8], ad: &[u8]) -> Result<(SingleVRFProof, VRFOutput), CryptoError> {
        let input = Input::new(data)
            .ok_or(CryptoError::InvalidInput("Failed to create VRF input from data".to_string()))?;
        let output = key_pair.secret.output(input);
        let proof = IetfProver::prove(&key_pair.secret, input, output, ad);
        Ok((SingleVRFProof { proof }, VRFOutput { output }))
    }

    /// Verify a VRF proof and output for a data using a public key
    #[staticmethod]
    fn verify(public_key_bytes: &[u8], data: &[u8], ad: &[u8], proof: &SingleVRFProof, output: &VRFOutput) -> Result<bool, CryptoError> {
        let public = Public::deserialize_compressed(&mut &public_key_bytes[..])
            .map_err(wrap_serialization_error)?;
        let input = Input::new(data)
            .ok_or(CryptoError::InvalidInput("Failed to create VRF input from data".to_string()))?;
        IetfVerifier::verify(&public, input, output.output, ad, &proof.proof)
        .map_err(wrap_vrf_error)?;
        Ok(true)
    }
}

/// VRF operations for ring signatures
#[pyclass]
pub struct RingVRF {
    ring_public_keys: Vec<AffinePoint>,
}

#[pymethods]
impl RingVRF {
    #[new]
    fn new(ring_public_keys: Vec<Vec<u8>>) -> Result<Self, CryptoError> {
        if ring_public_keys.is_empty() {
            return Err(CryptoError::InvalidInput("Ring public keys list cannot be empty".to_string()));
        }
        
        let mut parsed_keys = Vec::with_capacity(ring_public_keys.len());
        for pk_bytes in ring_public_keys {
            let affine = AffinePoint::deserialize_compressed(&mut &pk_bytes[..])
                .map_err(wrap_serialization_error)?;
            parsed_keys.push(affine);
        }
        
        Ok(Self {
            ring_public_keys: parsed_keys
        })
    }

    /// Generate VRF proof and output using a key pair and a ring of public keys
    fn prove(
        &self,
        key_pair: &KeyPairVRF,
        ring_public_index: u16,
        data: &[u8],
        ad: &[u8]
    ) -> Result<(RingVRFProof, VRFOutput), CryptoError> {
        let input = Input::new(data)
            .ok_or_else(|| CryptoError::InvalidInput("Failed to create VRF input from data".to_string()))?;
        
        if &self.ring_public_keys.len() - 1 < ring_public_index.into() {
            return Err(CryptoError::InvalidInput("Ring public index out of range".to_string()));
        }
    
        let ring_ctx = get_ring_context(6)?;
        let prover_key = ring_ctx.prover_key(&self.ring_public_keys);
        let prover = ring_ctx.prover(prover_key, ring_public_index.into());

        let output = key_pair.secret.output(input);
        let proof = RingProver::prove(&key_pair.secret, input, output, ad, &prover);

        Ok((RingVRFProof { proof }, VRFOutput { output }))
    }

    /// Verify a ring VRF proof and output
    fn verify(
        &self,
        data: &[u8],
        ad: &[u8],
        proof: &RingVRFProof,
        output: &VRFOutput,
    ) -> Result<bool, CryptoError> {
        let input = Input::new(data)
            .ok_or_else(|| CryptoError::InvalidInput("Failed to create VRF input from data".to_string()))?;

        let ring_ctx = get_ring_context(6)?;
        let verifier_key = ring_ctx.verifier_key(&self.ring_public_keys);
        let verifier = ring_ctx.verifier(verifier_key);

        <Public as RingVerifier<BandersnatchSha512Ell2>>::verify(input, output.output, ad, &proof.proof, &verifier).map_err(wrap_vrf_error)?;

        Ok(true)
    }

    /// Generate bandersnatch root from stored ring public keys
    fn root<'py>(&self, py: Python<'py>) -> Result<Py<PyBytes>, CryptoError> {
        let ring_ctx = get_ring_context(6)?;
        let verifier_key = ring_ctx.verifier_key(&self.ring_public_keys);
        let commitment = verifier_key.commitment();

        let mut bytes: Vec<u8> = Vec::new();
        commitment.serialize_compressed(&mut bytes)
            .map_err(wrap_serialization_error)?;

        Ok(PyBytes::new(py, &bytes).into())
    }
}

/// Python module
#[pymodule]
fn cryptography(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<KeyPairVRF>()?;
    m.add_class::<VRFOutput>()?;
    m.add_class::<SingleVRFProof>()?;
    m.add_class::<RingVRFProof>()?;
    m.add_class::<SingleVRF>()?;
    m.add_class::<RingVRF>()?;
    Ok(())
}
