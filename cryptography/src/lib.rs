use ark_ec_vrfs::{
    ietf::{self, Prover as IetfProver, Verifier as IetfVerifier},
    ring::{self, Prover as RingProver, Verifier as RingVerifier},
    suites::bandersnatch::edwards::BandersnatchSha512Ell2,
    Input, Output, Public, Secret, Error as VrfError,
};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, SerializationError};
use pyo3::prelude::*;
use pyo3::exceptions::{PyValueError, PyRuntimeError};
use pyo3::types::PyBytes;

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

/// VRF proof and output for single signatures
#[pyclass]
pub struct SingleVRFOutput {
    proof: ietf::Proof<BandersnatchSha512Ell2>,
    output: Output<BandersnatchSha512Ell2>,
}

#[pymethods]
impl SingleVRFOutput {
    /// Get the serialized proof bytes
    fn proof_bytes<'py>(&self, py: Python<'py>) -> Result<&'py PyBytes, CryptoError> {
        let mut bytes = Vec::new();
        self.proof.serialize_uncompressed(&mut bytes)
            .map_err(wrap_serialization_error)?;
        Ok(PyBytes::new(py, &bytes))
    }

    /// Get the serialized output bytes
    fn output_bytes<'py>(&self, py: Python<'py>) -> Result<&'py PyBytes, CryptoError> {
        let mut bytes = Vec::new();
        self.output.serialize_uncompressed(&mut bytes)
            .map_err(wrap_serialization_error)?;
        Ok(PyBytes::new(py, &bytes))
    }
}

/// VRF proof and output for ring signatures
#[pyclass]
pub struct RingVRFOutput {
    proof: ring::Proof<BandersnatchSha512Ell2>,
    output: Output<BandersnatchSha512Ell2>,
}

#[pymethods]
impl RingVRFOutput {
    /// Get the serialized proof bytes
    fn proof_bytes<'py>(&self, py: Python<'py>) -> Result<&'py PyBytes, CryptoError> {
        let mut bytes = Vec::new();
        self.proof.serialize_uncompressed(&mut bytes)
            .map_err(wrap_serialization_error)?;
        Ok(PyBytes::new(py, &bytes))
    }

    /// Get the serialized output bytes
    fn output_bytes<'py>(&self, py: Python<'py>) -> Result<&'py PyBytes, CryptoError> {
        let mut bytes = Vec::new();
        self.output.serialize_uncompressed(&mut bytes)
            .map_err(wrap_serialization_error)?;
        Ok(PyBytes::new(py, &bytes))
    }
}

/// VRF key pair for both single and ring signatures
#[pyclass]
pub struct KeyPairVRF {
    secret: Secret<BandersnatchSha512Ell2>,
}

#[pymethods]
impl KeyPairVRF {
    #[new]
    fn new() -> Self {
        let mut rng: ark_std::rand::prelude::ThreadRng = ark_std::rand::thread_rng();
        let secret = Secret::<BandersnatchSha512Ell2>::from_rand(&mut rng);
        Self { secret }
    }

    /// Get the serialized public key
    fn public_key_bytes<'py>(&self, py: Python<'py>) -> Result<&'py PyBytes, CryptoError> {
        let mut bytes = Vec::new();
        self.secret.public.0.serialize_uncompressed(&mut bytes)
            .map_err(wrap_serialization_error)?;
        Ok(PyBytes::new(py, &bytes))
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
    fn prove(key_pair: &KeyPairVRF, data: &[u8], ad: &[u8]) -> Result<SingleVRFOutput, CryptoError> {
        let input = Input::new(data)
            .ok_or(CryptoError::InvalidInput("Failed to create VRF input from data".to_string()))?;
        let output = key_pair.secret.output(input);
        let proof = IetfProver::prove(&key_pair.secret, input, output, ad);
        Ok(SingleVRFOutput { proof, output })
    }

    /// Verify a VRF proof and output for a data using a public key
    #[staticmethod]
    fn verify(public_key_bytes: &[u8], data: &[u8], ad: &[u8], vrf_outputs: &SingleVRFOutput) -> Result<bool, CryptoError> {
        let public = Public::<BandersnatchSha512Ell2>::deserialize_uncompressed(&mut &public_key_bytes[..])
            .map_err(wrap_serialization_error)?;
        let input = Input::new(data)
            .ok_or(CryptoError::InvalidInput("Failed to create VRF input from data".to_string()))?;
        IetfVerifier::verify(&public, input, vrf_outputs.output, ad, &vrf_outputs.proof)
        .map_err(wrap_vrf_error)?;
        Ok(true)
    }
}

/// VRF operations for ring signatures
#[pyclass]
pub struct RingVRF;

#[pymethods]
impl RingVRF {
    #[new]
    fn new() -> Self {
        Self
    }

    /// Generate VRF proof and output using a key pair and a ring of public keys
    #[staticmethod]
    fn prove(
        key_pair: &KeyPairVRF,
        ring_public_keys: Vec<&[u8]>,
        ring_public_index: u16,
        data: &[u8],
        ad: &[u8]
    ) -> Result<RingVRFOutput, CryptoError> {
        if ring_public_keys.is_empty() {
            return Err(CryptoError::InvalidInput("Ring public keys list cannot be empty".to_string()));
        }

        let input = Input::new(data)
            .ok_or_else(|| CryptoError::InvalidInput("Failed to create VRF input from data".to_string()))?;
        
        let mut ring_pks = Vec::with_capacity(ring_public_keys.len());
        for pk_bytes in ring_public_keys.iter() {
            let pk = Public::<BandersnatchSha512Ell2>::deserialize_uncompressed(&mut &pk_bytes[..])
                .map_err(wrap_serialization_error)?;
            ring_pks.push(pk);
        }
        if ring_pks.len() - 1 < ring_public_index.into() {
            return Err(CryptoError::InvalidInput("Ring public index out of range".to_string()));
        }

        let ring_ctx = ring::RingContext::<BandersnatchSha512Ell2>::from_seed(
            ring_pks.len(),
            [0u8; 32], // Temp fixed seed
        );

        let prover_key = ring_ctx.prover_key(&ring_pks.iter().map(|pk| pk.0).collect::<Vec<_>>());
        let prover = ring_ctx.prover(prover_key, ring_public_index.into());

        let output = key_pair.secret.output(input);
        let proof = RingProver::prove(&key_pair.secret, input, output, ad, &prover);

        Ok(RingVRFOutput { proof, output })
    }

    /// Verify a ring VRF proof and output
    #[staticmethod]
    fn verify(
        ring_public_keys: Vec<&[u8]>,
        data: &[u8],
        ad: &[u8],
        proof_and_output: &RingVRFOutput,
    ) -> Result<bool, CryptoError> {
        if ring_public_keys.is_empty() {
            return Err(CryptoError::InvalidInput("Ring public keys list cannot be empty".to_string()));
        }

        let input = Input::new(data)
            .ok_or_else(|| CryptoError::InvalidInput("Failed to create VRF input from data".to_string()))?;
        
        let mut ring_pks = Vec::with_capacity(ring_public_keys.len());
        for pk_bytes in ring_public_keys.iter() {
            let pk = Public::<BandersnatchSha512Ell2>::deserialize_uncompressed(&mut &pk_bytes[..])
                .map_err(wrap_serialization_error)?;
            ring_pks.push(pk);
        }

        let ring_ctx = ring::RingContext::<BandersnatchSha512Ell2>::from_seed(
            ring_pks.len(),
            [0u8; 32], // Temp fixed seed
        );

        let verifier_key = ring_ctx.verifier_key(&ring_pks.iter().map(|pk| pk.0).collect::<Vec<_>>());
        let verifier = ring_ctx.verifier(verifier_key);

        <Public<BandersnatchSha512Ell2> as RingVerifier<BandersnatchSha512Ell2>>::verify(input, proof_and_output.output, ad, &proof_and_output.proof, &verifier).map_err(wrap_vrf_error)?;

        Ok(true)
    }
}

/// Python module
#[pymodule]
fn cryptography(_py: Python<'_>, m: &PyModule) -> PyResult<()> {
    m.add_class::<KeyPairVRF>()?;
    m.add_class::<SingleVRFOutput>()?;
    m.add_class::<RingVRFOutput>()?;
    m.add_class::<SingleVRF>()?;
    m.add_class::<RingVRF>()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_single_signature_vrf() {
        // Initialize Python
        pyo3::prepare_freethreaded_python();

        // Generate key pair
        let key_pair = KeyPairVRF::new();
        let data = b"test data";
        let ad = b"additional data";

        // Generate proof and output
        let proof_and_output = SingleVRF::prove(&key_pair, data, ad).unwrap();

        // Verify proof
        Python::with_gil(|py| {
            let pk_bytes = key_pair.public_key_bytes(py).unwrap();
            let result = SingleVRF::verify(pk_bytes.as_bytes(), data, ad, &proof_and_output).unwrap();
            assert!(result);
        });
    }

    #[test]
    fn test_ring_signature_vrf() {
        // Initialize Python
        pyo3::prepare_freethreaded_python();

        // Generate multiple key pairs for the ring
        let key_pair1 = KeyPairVRF::new();
        let key_pair2 = KeyPairVRF::new();
        let key_pair3 = KeyPairVRF::new();

        Python::with_gil(|py| {
            let pk1_bytes = key_pair1.public_key_bytes(py).unwrap();
            let pk2_bytes = key_pair2.public_key_bytes(py).unwrap();
            let pk3_bytes = key_pair3.public_key_bytes(py).unwrap();

            let ring_public_keys = vec![
                pk1_bytes.as_bytes(),
                pk2_bytes.as_bytes(),
                pk3_bytes.as_bytes(),
            ];

            let data = b"test data";
            let ad = b"additional data";

            // Generate proof and output using first key pair
            let proof_and_output = RingVRF::prove(&key_pair1, ring_public_keys.clone(), 0, data, ad).unwrap();

            // Verify proof
            let result = RingVRF::verify(ring_public_keys, data, ad, &proof_and_output).unwrap();
            assert!(result);
        });
    }
}
