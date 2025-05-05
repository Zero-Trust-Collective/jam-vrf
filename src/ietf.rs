use crate::errors::{wrap_serialization_error, wrap_vrf_error, CryptoError};
use crate::vrf_output::VRFOutput;
use ark_vrf::ietf::Verifier;
use ark_vrf::reexports::ark_serialize::CanonicalDeserialize;
use ark_vrf::suites::bandersnatch::{IetfProof, Input, Public};
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;

/// Verify an IETF signature against some data & additional data
///
/// **Args:**
/// - public_key: `bytes` - bandersnatch public key
/// - data: `bytes`
/// - ad: `bytes` - additional data
/// - signature: `bytes`
///
/// **Raises:**
/// - `ValueError` - invalid signature
/// - `Exception` - internal error
///
/// **Example:**
/**```
try:
    ietf_verify(public_key, data, ad, signature)
except ValueError:
    print("invalid signature!")
```*/
#[pyfunction]
pub fn ietf_verify(public_key: &[u8], data: &[u8], ad: &[u8], signature: &[u8]) -> PyResult<()> {
    // deserialize public key
    let public =
        Public::deserialize_compressed(&public_key[..]).map_err(wrap_serialization_error)?;

    // construct vrf input
    let input = Input::new(data).ok_or(CryptoError::InvalidInput(
        "Failed to create VRF input from data".to_string(),
    ))?;

    // construct vrf output
    let output = VRFOutput::new(signature.get(..32).ok_or(PyValueError::new_err(
        "Unable to extract output from signature",
    ))?)?;

    // deserialize proof
    let proof = IetfProof::deserialize_compressed(signature.get(32..).ok_or(
        PyValueError::new_err("Unable to extract proof from signature"),
    )?)
    .map_err(wrap_serialization_error)?;

    // verify signature
    Verifier::verify(&public, input, output.0, ad, &proof).map_err(wrap_vrf_error)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::ietf_verify;
    use serde;
    use serde::Deserialize;
    use serde_json::Value;
    use serde_with::hex::Hex;
    use serde_with::serde_as;
    use std::fs::File;
    use std::io::BufReader;

    #[serde_as]
    #[derive(Deserialize)]
    pub struct IETF {
        #[serde_as(as = "Hex")]
        pub public_key: Vec<u8>,
        #[serde_as(as = "Hex")]
        pub data: Vec<u8>,
        #[serde_as(as = "Hex")]
        pub additional_data: Vec<u8>,
        #[serde_as(as = "Hex")]
        pub signature: Vec<u8>,
    }

    #[test]
    fn test_signature_verification() {
        // load mock data
        let file = File::open("mocks.json").unwrap();
        let reader = BufReader::new(file);
        let mock_json: Value = serde_json::from_reader(reader).unwrap();
        let mock: IETF = serde_json::from_value(mock_json["ietf"].clone()).unwrap();

        // verify valid signature
        ietf_verify(
            &mock.public_key,
            &mock.data,
            &mock.additional_data,
            &mock.signature,
        )
        .expect("signature verification should pass");

        // verify invalid signature (wrong data)
        let result = ietf_verify(
            &mock.public_key,
            b"wrong_data",
            &mock.additional_data,
            &mock.signature,
        );
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().to_string(),
            "ValueError: VRF verification failed"
        );

        // verify invalid signature (wrong ad)
        let result = ietf_verify(&mock.public_key, &mock.data, b"wrong_ad", &mock.signature);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().to_string(),
            "ValueError: VRF verification failed"
        );
    }
}
