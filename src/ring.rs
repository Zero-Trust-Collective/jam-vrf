use crate::errors::{wrap_serialization_error, wrap_vrf_error, CryptoError};
use crate::vrf_output::VRFOutput;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_vrf::reexports::ark_serialize;
use ark_vrf::ring::Verifier as VerifierTrait;
use ark_vrf::suites::bandersnatch::{
    AffinePoint, Input, PcsParams, Public, RingCommitment, RingProof, RingProofParams,
    RingVerifier as ArkRingVerifier,
};
use pyo3::exceptions::{PyException, PyValueError};
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use rayon::iter::{IntoParallelRefIterator, ParallelIterator};
use std::collections::HashMap;
use std::sync::OnceLock;

static SRS_PARAMS: OnceLock<PcsParams> = OnceLock::new();

// Embed the parameters file directly into the binary
const SRS: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/parameters/zcash-srs-2-11-uncompressed.bin"
));

/// Get the polynomial commitment scheme paramaters used in JAM
fn get_pcs_params() -> PcsParams {
    SRS_PARAMS
        .get_or_init(|| {
            PcsParams::deserialize_uncompressed(&SRS[..])
                .expect("Failed to deserialize embedded SRS parameters")
        })
        .clone()
}

/// Compute the ring commitment for an ordered list of public keys
///
/// **Args:**
/// - public_keys: `List[bytes]` - bandersnatch public keys
///
/// **Returns:**
/// - `bytes`: object that represents the ring commitment
///
/// **Raises:**
/// - `ValueError` - invalid or empty input keys
/// - `Exception` - internal error
///
/// **Example**
/**```
try:
    commitment = get_ring_commitment(public_keys)
except Exception:
    ...
```*/
#[pyfunction]
pub fn get_ring_commitment(py: Python<'_>, public_keys: Vec<Vec<u8>>) -> PyResult<Py<PyBytes>> {
    // verify the ring isn't empty
    if public_keys.is_empty() {
        return Err(PyValueError::new_err("Public keys list cannot be empty"));
    }

    // get the pcs paramaters
    let pc_params = get_pcs_params();

    // construct the ring parameters
    let params = RingProofParams::from_pcs_params(public_keys.len(), pc_params)
        .map_err(|e| PyException::new_err(format!("unable to initialize ring params: {:?}", e)))?;

    // deserialize the keys, substituting the padding point for any invalid keys
    let parsed_keys: Vec<AffinePoint> = public_keys
        .iter()
        .map(|pk| {
            AffinePoint::deserialize_compressed(&pk[..]).unwrap_or(RingProofParams::padding_point())
        })
        .collect();

    // construct verifier key
    let verifier_key = params.verifier_key(&parsed_keys);

    // return serialized commitment
    let commitment = verifier_key.commitment();
    let mut bytes = Vec::new();
    commitment
        .serialize_compressed(&mut bytes)
        .map_err(|e| PyException::new_err(format!("Failed to serialize commitment: {}", e)))?;
    Ok(PyBytes::new(py, &bytes).into())
}

/// Used for verifying ring signatures
///
/// **Constructor Args:**
/// - commitment: `bytes` - ring commitment
/// - ring_size: `int` - number of keys in the ring
///
/// **Raises:**
/// - `Exception` - internal error
///
/// **Example:**
/**```
try:
    verifier = RingVerifier(commitment, ring_size)
except Exception:
    ...
```*/
#[pyclass]
pub struct RingVerifier(ArkRingVerifier);

#[pymethods]
impl RingVerifier {
    /// Construct a ring verifier from a commitment & ring size
    #[new]
    fn new(commitment: &[u8], ring_size: usize) -> PyResult<Self> {
        // deserialize commitment
        let commitment = RingCommitment::deserialize_compressed(&commitment[..])
            .map_err(wrap_serialization_error)?;

        // get pcs parameters
        let pc_params = get_pcs_params();

        let params = RingProofParams::from_pcs_params(ring_size, pc_params).map_err(|e| {
            CryptoError::InvalidInput(format!("unable to initialize ring params: {:?}", e))
        })?;

        // construct & return verifier
        let verifier_key = params.verifier_key_from_commitment(commitment);
        let verifier = params.verifier(verifier_key);
        Ok(Self(verifier))
    }

    /// Verify a batch of ring signatures
    ///
    /// **Args:**
    /// -
    /// - batch: [(data, additional data, signature)] - collection of data & signatures to be verified. All of the tuple fields are python bytes type.
    ///
    /// **Raises:**
    /// - `ValueError(Dict{index: PyErr})` - a dictionary mapping invalid indexes to validation errors
    /// - `Exception` - internal error
    ///
    /// **Example:**
    /**
    verifier: RingVerifier

    try:
        verifier.verify([data, ad, signature], [data, ad, signature])
    except ValueError as e:
        for batch_index, error in e.args[0].items():
            print("batch index {} produced error: {}".format(batch_index, error))
    */
    fn verify(&self, batch: Vec<(Vec<u8>, Vec<u8>, Vec<u8>)>) -> PyResult<()> {
        let max_signatures = usize::MAX;
        if batch.len() > max_signatures.into() {
            return Err(PyValueError::new_err(format!(
                "Batch cannot contain more than {} items!",
                max_signatures
            )));
        }
        let verification_results: Vec<Result<(), PyErr>> = batch
            .par_iter()
            .map(|(data, ad, signature)| {
                // construct vrf input
                let input = Input::new(data).ok_or_else(|| {
                    PyErr::from(CryptoError::InvalidInput(
                        "Failed to create VRF input from data".to_string(),
                    ))
                })?;

                // construct vrf output
                let output = VRFOutput::new(signature.get(..32).ok_or(PyErr::from(
                    CryptoError::InvalidInput(
                        "Unable to extract output from signature".to_string(),
                    ),
                ))?)?;

                // deserialize proof
                let proof = RingProof::deserialize_compressed(signature.get(32..).ok_or(
                    PyErr::from(CryptoError::InvalidInput(
                        "Unable to extract proof from signature".to_string(),
                    )),
                )?)
                .map_err(wrap_serialization_error)?;

                // verify signature
                Public::verify(input, output.0, ad, &proof, &self.0)
                    .map_err(wrap_vrf_error)
                    .map_err(|e| e.into())
            })
            .collect();

        // if any of the signatures are invalid, return a PyErr containing an errors dictionary
        // the errors dictionary maps batch indexes to verification errors
        if verification_results.iter().any(|r| r.is_err()) {
            let mut invalid_signatures: HashMap<usize, PyErr> = HashMap::new();
            for (i, result) in verification_results.into_iter().enumerate() {
                if let Err(e) = result {
                    invalid_signatures.insert(i, e);
                }
            }
            return Err(PyValueError::new_err(invalid_signatures));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{get_ring_commitment, RingVerifier};
    use pyo3::prelude::*;
    use pyo3::Python;
    use serde;
    use serde::Deserialize;
    use serde_json::Value;
    use serde_with::hex::Hex;
    use serde_with::serde_as;
    use std::fs::File;
    use std::io::BufReader;

    #[serde_as]
    #[derive(Deserialize)]
    pub struct SafroleTicket {
        pub attempt: u8,
        #[serde_as(as = "Hex")]
        pub root: Vec<u8>,
        #[serde_as(as = "Hex")]
        pub entropy: Vec<u8>,
        pub ring_size: usize,
        #[serde_as(as = "Hex")]
        pub signature: Vec<u8>,
    }

    #[serde_as]
    #[derive(Deserialize)]
    pub struct COMMITMENT {
        #[serde_as(as = "Vec<Hex>")]
        pub keys: Vec<Vec<u8>>,
        #[serde_as(as = "Hex")]
        pub expected_commitment: Vec<u8>,
    }

    #[test]
    fn test_commitment_generation() {
        // load mock data
        let file = File::open("mocks.json").unwrap();
        let reader = BufReader::new(file);
        let mock_json: Value = serde_json::from_reader(reader).unwrap();
        let mock: COMMITMENT =
            serde_json::from_value(mock_json["ring"]["commitment"].clone()).unwrap();

        // generate & verify commitment
        Python::with_gil(|py| {
            let commitment = get_ring_commitment(py, mock.keys).unwrap();
            assert_eq!(commitment.as_bytes(py), mock.expected_commitment.as_slice());
        });
    }

    #[test]
    fn test_signature_verification() {
        // load mock data
        let file = File::open("mocks.json").unwrap();
        let reader = BufReader::new(file);
        let mock_json: Value = serde_json::from_reader(reader).unwrap();
        let mock: SafroleTicket =
            serde_json::from_value(mock_json["ring"]["safrole_ticket"].clone()).unwrap();

        // construct ring verifier
        let verifier = RingVerifier::new(&mock.root, mock.ring_size).unwrap();

        // generate batch of valid signatures
        let mut data = Vec::new();
        data.extend_from_slice(b"jam_ticket_seal");
        data.extend(mock.entropy);
        data.push(mock.attempt);
        let mut batch = vec![];
        for _ in 0..2 {
            batch.push((data.clone(), vec![], mock.signature.clone()));
        }

        // verify valid signatures
        verifier
            .verify(batch.clone())
            .expect("signature verification should pass");

        // append a few bad signatures to our batch
        batch.push((data.clone(), b"wrong_ad".to_vec(), mock.signature.clone())); // ad is different from what was signed
        batch.push((b"wrong_data".to_vec(), b"".to_vec(), mock.signature.clone())); // data is different from what was signed

        // verify batch that contains invalid signatures
        let result = verifier.verify(batch);
        // signature verification should raise an error
        assert!(result.is_err());
        // verify the error contains a dict identifying each of the invalid signatures
        Python::with_gil(|py| {
            let invalid_signatures = result
                .unwrap_err()
                .value(py)
                .getattr("args")
                .unwrap()
                .get_item(0)
                .unwrap();
            assert_eq!(invalid_signatures.len().unwrap(), 2);

            let invalid_batch_indices = [2, 3];
            for i in invalid_batch_indices {
                let err = invalid_signatures.get_item(i).unwrap().str().unwrap();
                assert_eq!(err, "VRF verification failed");
            }
        })
    }
}
