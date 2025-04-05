use crate::errors::{wrap_serialization_error, wrap_vrf_error, CryptoError};
use crate::vrf_output::VRFOutput;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_vrf::{ietf::Verifier as IetfVerifier, reexports::ark_serialize, suites::bandersnatch};
use bandersnatch::{IetfProof, Input, Public};
use pyo3::prelude::*;
use pyo3::types::PyBytes;

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

#[cfg(test)]
mod tests {
    use super::{SingleVRFProof, SingleVRFVerifier, VRFOutput};

    #[test]
    fn test_ietf_verify() {
        // vector 7
        // https://github.com/davxy/bandersnatch-vrf-spec/blob/6b1ceba5b3cbc834201732bcdad1377e19e9283e/assets/vectors/bandersnatch_sha-512_ell2_ietf.json#L81
        let public_key =
            hex::decode("b0e1f208f9d6e5b310b92014ea7ef3011e649dab038804759f3766e01029d623")
                .unwrap();
        let data = hex::decode("42616e646572736e6174636820766563746f72").unwrap();
        let ad = hex::decode("1f42").unwrap();
        let output = VRFOutput::new(
            hex::decode("6d1dd583bea262323c7dc9e94e57a472e09874e435719010eeafae503c433f16")
                .unwrap()
                .as_slice(),
        )
        .unwrap();
        let proof = SingleVRFProof::new(hex::decode("6dbeeab9648505fa6a95de52d611acfbb2febacc58cdc7d0ca45abd8c952ef12ce7f4a2354a6c3f97aee6cc60c6aa4c4430b12ed0f0ef304b326c776618d7609").unwrap().as_slice()).unwrap();

        // Create verifier and verify reconstructed proof and output
        let verifier = SingleVRFVerifier::new();
        let result = verifier.verify(&public_key, &data, &ad, &output, &proof);
        assert!(result.is_ok());
    }
}
