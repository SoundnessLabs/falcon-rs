//! Error types for Falcon operations.

use core::fmt;

/// Errors that can occur during Falcon operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// Random number generation failed.
    ///
    /// This typically occurs when trying to use system RNG in environments
    /// where it's not available (e.g., WASM without `getrandom`).
    Random,

    /// Buffer too small for the operation.
    ///
    /// This should not occur when using the high-level API, as buffer sizes
    /// are computed automatically.
    BufferTooSmall,

    /// Invalid format in key or signature.
    ///
    /// The provided bytes do not represent a valid Falcon key or signature.
    InvalidFormat,

    /// Signature verification failed.
    ///
    /// The signature does not match the message and public key.
    BadSignature,

    /// Invalid argument provided.
    ///
    /// A parameter is out of its valid range.
    InvalidArgument,

    /// Internal error (should not happen).
    ///
    /// This indicates a bug in the implementation.
    Internal,
}

impl Error {
    /// Convert a Falcon C library error code to a Rust error.
    ///
    /// Returns `None` if the code indicates success (0).
    #[inline]
    pub(crate) fn from_code(code: i32) -> Option<Self> {
        match code {
            0 => None,
            -1 => Some(Error::Random),
            -2 => Some(Error::BufferTooSmall),
            -3 => Some(Error::InvalidFormat),
            -4 => Some(Error::BadSignature),
            -5 => Some(Error::InvalidArgument),
            -6 => Some(Error::Internal),
            _ => Some(Error::Internal),
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Random => write!(f, "random number generation failed"),
            Error::BufferTooSmall => write!(f, "buffer too small"),
            Error::InvalidFormat => write!(f, "invalid format"),
            Error::BadSignature => write!(f, "invalid signature"),
            Error::InvalidArgument => write!(f, "invalid argument"),
            Error::Internal => write!(f, "internal error"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}

/// A specialized `Result` type for Falcon operations.
pub type Result<T> = core::result::Result<T, Error>;
