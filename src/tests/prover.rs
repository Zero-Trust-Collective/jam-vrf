use crate::srs::get_pcs_params;
use crate::{wrap_serialization_error, CryptoError, RingVRFProof, SingleVRFProof, VRFOutput};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_vrf::{
    ietf::Prover as IetfProver, reexports::ark_serialize, ring::Prover as RingProver,
    suites::bandersnatch,
};
use bandersnatch::{
    AffinePoint, Input, RingProofParams, RingProver as BandersnatchRingProver, Secret,
};
use pyo3::prelude::*;
use pyo3::types::PyBytes;

/// VRF key pair for both single and ring signatures
pub struct KeyPairVRF {
    secret: Secret,
}

impl KeyPairVRF {
    pub fn new() -> Self {
        let mut rng: ark_std::rand::prelude::ThreadRng = ark_std::rand::thread_rng();
        let secret = Secret::from_rand(&mut rng);
        Self { secret }
    }

    /// Get the serialized public key
    pub fn public_key<'py>(&self, py: Python<'py>) -> Result<Py<PyBytes>, CryptoError> {
        let mut bytes = Vec::new();
        self.secret
            .public
            .0
            .serialize_compressed(&mut bytes)
            .map_err(wrap_serialization_error)?;
        Ok(PyBytes::new(py, &bytes).into())
    }
}

/// VRF prover for single signatures
pub struct SingleVRFProver;

impl SingleVRFProver {
    pub fn new() -> Self {
        Self
    }

    /// Generate VRF proof and output for a data using a key pair
    pub fn prove(
        &self,
        key_pair: &KeyPairVRF,
        data: &[u8],
        ad: &[u8],
    ) -> Result<(SingleVRFProof, VRFOutput), CryptoError> {
        let input = Input::new(data).ok_or(CryptoError::InvalidInput(
            "Failed to create VRF input from data".to_string(),
        ))?;
        let output = key_pair.secret.output(input);
        let proof = IetfProver::prove(&key_pair.secret, input, output, ad);
        Ok((SingleVRFProof { proof }, VRFOutput { output }))
    }
}

/// VRF prover for ring signatures
pub struct RingVRFProver {
    prover: BandersnatchRingProver,
}

impl RingVRFProver {
    /// Create a new RingVRFProver instance from a list of public keys and ring index
    pub fn new(public_keys: Vec<Vec<u8>>, ring_public_index: u16) -> Result<Self, CryptoError> {
        if public_keys.is_empty() {
            return Err(CryptoError::InvalidInput(
                "Ring public keys list cannot be empty".to_string(),
            ));
        }

        let pc_params = get_pcs_params();

        let params =
            RingProofParams::from_pcs_params(public_keys.len(), pc_params).map_err(|e| {
                CryptoError::InvalidInput(format!("unable to initialize ring params: {:?}", e))
            })?;

        let parsed_keys: Vec<AffinePoint> = public_keys
            .iter()
            .map(|pk| {
                AffinePoint::deserialize_compressed(&pk[..])
                    .unwrap_or(RingProofParams::padding_point())
            })
            .collect();

        let ring_index = ring_public_index as usize;
        if ring_index >= parsed_keys.len() {
            return Err(CryptoError::InvalidInput(
                "Ring public index out of range".to_string(),
            ));
        }

        let prover_key = params.prover_key(&parsed_keys);
        let prover = params.prover(prover_key, ring_index);

        Ok(Self { prover })
    }

    /// Generate VRF proof and output using a key pair
    pub fn prove(
        &self,
        key_pair: &KeyPairVRF,
        data: &[u8],
        ad: &[u8],
    ) -> Result<(RingVRFProof, VRFOutput), CryptoError> {
        let input = Input::new(data).ok_or_else(|| {
            CryptoError::InvalidInput("Failed to create VRF input from data".to_string())
        })?;

        let output = key_pair.secret.output(input);
        let proof = RingProver::prove(&key_pair.secret, input, output, ad, &self.prover);

        Ok((RingVRFProof { proof }, VRFOutput { output }))
    }
}
