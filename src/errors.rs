use ark_serialize::SerializationError;
use ark_vrf::{reexports::ark_serialize, Error as VrfError};
use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;

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

pub fn wrap_vrf_error(err: VrfError) -> CryptoError {
    CryptoError::VrfError(VrfErrorWrapper(err))
}

pub fn wrap_serialization_error(err: SerializationError) -> CryptoError {
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
            CryptoError::SerializationError(SerializationErrorWrapper(
                SerializationError::NotEnoughSpace,
            )) => PyValueError::new_err("Not enough space for serialization"),
            CryptoError::SerializationError(SerializationErrorWrapper(
                SerializationError::InvalidData,
            )) => PyValueError::new_err("Invalid serialized data format"),
            CryptoError::SerializationError(SerializationErrorWrapper(
                SerializationError::UnexpectedFlags,
            )) => PyRuntimeError::new_err("Unknown serialization error"),
            CryptoError::SerializationError(SerializationErrorWrapper(
                SerializationError::IoError(_),
            )) => PyRuntimeError::new_err("IO error during serialization"),
            CryptoError::InvalidInput(data) => PyValueError::new_err(data),
        }
    }
}
