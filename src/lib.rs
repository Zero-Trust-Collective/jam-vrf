use pyo3::prelude::*;

mod errors;
mod ietf;
mod ring;
mod vrf_output;

/// Python module
#[pymodule]
fn jam_vrf(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<ring::RingVerifier>()?;
    m.add_function(wrap_pyfunction!(ring::get_ring_commitment, m)?)?;
    m.add_function(wrap_pyfunction!(ietf::ietf_verify, m)?)?;
    Ok(())
}
