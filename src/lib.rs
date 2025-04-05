use pyo3::prelude::*;

mod errors;
mod ietf;
mod ring;
mod vrf_output;

/// Python module
#[pymodule]
fn pyvrf(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<vrf_output::VRFOutput>()?;
    m.add_class::<ietf::IetfVRFProof>()?;
    m.add_class::<ring::RingVRFProof>()?;
    m.add_class::<ring::RingVRFVerifier>()?;
    m.add_function(wrap_pyfunction!(ring::get_ring_commitment, m)?)?;
    m.add_function(wrap_pyfunction!(ietf::ietf_verify, m)?)?;
    Ok(())
}
