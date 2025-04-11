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
/// - commitment: `bytes` - ring commitment (in JAM this is called a **ring root**)
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

    /// Verify a ring signature against some data & additional data
    ///
    /// **Args:**
    /// - data: `bytes`
    /// - ad: `bytes` - additional data
    /// - signature: `bytes` - ring signature
    ///
    /// **Raises:**
    /// - `ValueError` - invalid signature
    /// - `Exception` - internal error
    ///
    /// **Example:**
    /**
    verifier: RingVerifier

    try:
        verifier.verify(data, ad, signature)
    except ValueError :
        print("invalid signature!")
    */
    fn verify(&self, data: &[u8], ad: &[u8], signature: &[u8]) -> PyResult<()> {
        // construct vrf input
        let input = Input::new(data).ok_or_else(|| {
            CryptoError::InvalidInput("Failed to create VRF input from data".to_string())
        })?;

        // construct vrf output
        let output = VRFOutput::new(signature.get(..32).ok_or(PyValueError::new_err(
            "Unable to extract output from signature",
        ))?)?;

        // deserialize proof
        let proof = RingProof::deserialize_compressed(signature.get(32..).ok_or(
            PyValueError::new_err("Unable to extract proof from signature"),
        )?)
        .map_err(wrap_serialization_error)?;

        // verify signature
        Public::verify(input, output.0, ad, &proof, &self.0).map_err(wrap_vrf_error)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{get_ring_commitment, RingVerifier};
    use pyo3::Python;

    #[test]
    fn test_ring_commitment() {
        // test vector sourced from: https://github.com/davxy/bandersnatch-vrf-spec/blob/6b1ceba5b3cbc834201732bcdad1377e19e9283e/assets/vectors/bandersnatch_sha-512_ell2_ring.json#L123
        let public_keys = vec![
            hex::decode("7b32d917d5aa771d493c47b0e096886827cd056c82dbdba19e60baa8b2c60313")
                .unwrap(),
            hex::decode("d3b1bdb321123449c6e89d310bc6b7f654315eb471c84778353ce08b951ad471")
                .unwrap(),
            hex::decode("561fdb0dcfb8bd443718b942f82fe717238cbcf8d12b8d22861c8a09a984a3c5")
                .unwrap(),
            hex::decode("b0e1f208f9d6e5b310b92014ea7ef3011e649dab038804759f3766e01029d623")
                .unwrap(),
            hex::decode("4fd11f89c2a1aaefe856bb1c5d4a1fad73f4de5e41804ca2c17ba26d6e10050c")
                .unwrap(),
            hex::decode("86d06ee2c70da6cf2da2a828d8a9d8ef755ad6e580e838359a10accb086ae437")
                .unwrap(),
            hex::decode("ad6fdeda0dde0a57c51d3226b87e3795e6474393772da46101fd597fbd456c1b")
                .unwrap(),
            hex::decode("3f9dc0c4f67f207974123830c2d66988fb3fb44becbbba5a64143f376edc51d9")
                .unwrap(),
        ];

        // Expected output commitment
        let expected_ring = hex::decode("a359e70e307799b111ad89b162b4260fb4a96ebf4232e8b02d396033498d4216305ed9cff3584a4c68f03ab3df87243a80bfc965633efc23c82ca064afe105baacccbf23e47b543d16c3c4466a83242a77acc16f79b8710051b5e97c85319cf392e630ae2b14e758ab0960e372172203f4c9a41777dadd529971d7ab9d23ab29fe0e9c85ec450505dde7f5ac038274cf").unwrap();

        // Generate root
        Python::with_gil(|py| {
            let commitment = get_ring_commitment(py, public_keys).unwrap();
            // Verify results
            assert_eq!(commitment.as_bytes(py), expected_ring.as_slice());
        });
    }

    #[test]
    fn test_ring_verify() {
        // Verify ring VRF signature of a jam ticket
        // testvector sourced from: https://github.com/davxy/jam-test-vectors/blob/polkajam-vectors/safrole/tiny/publish-tickets-no-mark-6.json
        let signature = hex::decode("1dfb7b61deee0c4a6899c1123e9e362f2b965079be576aebda0b7ac5e111186ec11372ea37a823a74a10a7d0c3b9b850d07ea9367f7560d0271a34125983fb0a4acb929b0817c4e3710915ea07e64d72198cbb2399e318940569d4c80ead4b5b39fa798e7a8327dcba940ffa77659b1850f877be7a439fc3a66191299d5ae92492d1a27a97455ca697913b3d7c7a9f95bfe58bda53a2641e4a0752f4efbb1a0417d77dedf11d514684f94b0729672a5808088b5445ceb540db00aa8934faa314a445e67a96d618c4fc1c100a69fa449cca1db6a7ac609d7bd04107f685411aa1bebecdb3897ed0d6c00b46a56381e5968b7520b215677afa1394464057709837dfb22b04b53c69011da7926c341cf6e77a2ed27912c40267c826cca53f876dad8a11740bbf7fec24eacf37246038a6da9d4fa923e40efb6d0a136ff2349fc1c6a1f0d199e87022d71cb503b9ea45a774988b0a3abe6f2a8bbeade7e72f14a27fd1fd2c34bf751a4397df18d16cea6ae40282ce51c36d85f5a90896070bcca248ecce27455c091c0f2e455ea83aaeac9b3c2df6cac95f34f7bd086746a414a3414f48f24f725ea802bc92a56a089f5af93122f85f7474380f3a3534553663ff34ea66f50ce876aa4bcec33ca5e7d0b16677c190d5c8365b3d55c3873b634ca53e988ca8860b97577f3b0265584b0544dde70556b35b86118c7b7c94232fb8fc30b6f407647ce39e40d0769e8a5d906f17a2ead9ab49ba3b3e669b3d48017ebf340e00a03ad82ad420ac3bc63b5f06cb15a0a938848a382ddaebabfe7b3ec13270f6c3e4c14aca85963f879bfc5937244bad613b0ed92f86205874a639fe758f3ab5c69222ea2460792c9c42732c74716886b2e8f9a155e5d439246bff0b21baf74f8e7b672c61f1328939f03be4e5d4dffa6f2d8231734a0ed8e82fef9dd00cb1ab1dfe37f0ddb12e1861570b6e4cab1ab80e774048227493bb8bad60df218b2a08e6d2230f1d040ce47e2d473d0e925b2a91abcb7f867ee2f41ad64409aa81a0937f130ebdf53e6ee61480c73708af790d1134b7a0b472573e1008b9c9d0ee95d40a3909d94e6cf0044d916ff9461844").unwrap();
        let ring_root = hex::decode("85f9095f4abd040839d793d89ab5ff25c61e50c844ab6765e2c0b22373b5a8f6fbe5fc0cd61fdde580b3d44fe1be127197e33b91960b10d2c6fc75aec03f36e16c2a8204961097dbc2c5ba7655543385399cc9ef08bf2e520ccf3b0a7569d88492e630ae2b14e758ab0960e372172203f4c9a41777dadd529971d7ab9d23ab29fe0e9c85ec450505dde7f5ac038274cf").unwrap();
        let entropy: Vec<u8> =
            hex::decode("bb30a42c1e62f0afda5f0a4e8a562f7a13a24cea00ee81917b86b89e801314aa")
                .unwrap();
        let ring_size = 6;

        // construct ring verifier
        let verifier = RingVerifier::new(&ring_root, ring_size).unwrap();

        // verify signature
        let mut data = Vec::new();
        data.extend_from_slice(b"jam_ticket_seal");
        data.extend_from_slice(entropy.as_slice());
        data.push(1);
        let ad = b"";
        verifier
            .verify(&data, ad, &signature)
            .expect("signature verification should pass");
    }
}
