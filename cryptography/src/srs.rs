use std::sync::OnceLock;
use std::fs::File;
use std::io::Read;
use ark_serialize::CanonicalDeserialize;
use ark_ec_vrfs::{
    ring,
    suites::bandersnatch::edwards::BandersnatchSha512Ell2,
};

static SRS_PARAMS: OnceLock<ring::PcsParams<BandersnatchSha512Ell2>> = OnceLock::new();

const DEFAULT_SRS_PATH: &str = "parameters/zcash-srs-2-11-uncompressed.bin";

pub fn get_pcs_params() -> ring::PcsParams<BandersnatchSha512Ell2> {
    SRS_PARAMS.get_or_init(|| {
        let srs_path = std::env::var("SRS_PATH").unwrap_or(DEFAULT_SRS_PATH.to_string());
        let mut file = File::open(srs_path).expect("Failed to open SRS file");
        let mut buf = Vec::new();
        file.read_to_end(&mut buf).expect("Failed to read SRS file");
        
        ring::PcsParams::<BandersnatchSha512Ell2>::deserialize_uncompressed(&mut &buf[..])
            .expect("Failed to deserialize SRS parameters")
    }).clone()
}
