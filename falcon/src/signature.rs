//! Signature types and formats.

extern crate alloc;

use alloc::vec::Vec;
use core::marker::PhantomData;

use falcon_sys as ffi;

use crate::{Error, FalconParams, Result};

/// Signature format options.
///
/// Falcon supports three signature formats with different trade-offs:
///
/// - **Compressed**: Variable length, smallest on average (~666 bytes for Falcon-512)
/// - **Padded**: Fixed length, slightly larger (~666 bytes for Falcon-512)
/// - **ConstantTime**: Fixed length, largest (~809 bytes for Falcon-512), constant-time
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SignatureFormat {
    /// Variable-length compressed format.
    ///
    /// This produces the smallest signatures on average, but the size varies
    /// depending on the specific signature value. Most signatures will be
    /// close to the average, but occasionally signatures may be slightly
    /// larger or smaller.
    Compressed,

    /// Fixed-length padded format.
    ///
    /// This is the compressed format with padding added to achieve a fixed size.
    /// Use this when you need predictable signature sizes.
    Padded,

    /// Constant-time format.
    ///
    /// This format is designed to be processed in constant time, preventing
    /// timing-based side channels on the signature value. It produces larger
    /// signatures than the other formats. Use this when the signed data is
    /// secret and you need to prevent timing attacks.
    ConstantTime,
}

impl SignatureFormat {
    /// Convert to the FFI signature type constant.
    #[inline]
    pub(crate) fn to_ffi(self) -> i32 {
        match self {
            SignatureFormat::Compressed => ffi::FALCON_SIG_COMPRESSED,
            SignatureFormat::Padded => ffi::FALCON_SIG_PADDED,
            SignatureFormat::ConstantTime => ffi::FALCON_SIG_CT,
        }
    }

    /// Detect format from a signature header byte.
    #[inline]
    fn from_header(header: u8) -> Option<Self> {
        match header & 0xF0 {
            0x30 => Some(SignatureFormat::Compressed), // Could also be Padded
            0x50 => Some(SignatureFormat::ConstantTime),
            _ => None,
        }
    }

    /// Get the maximum signature size for this format and parameter set.
    #[inline]
    pub fn max_size<P: FalconParams>(self) -> usize {
        match self {
            SignatureFormat::Compressed => P::SIG_COMPRESSED_MAXSIZE,
            SignatureFormat::Padded => P::SIG_PADDED_SIZE,
            SignatureFormat::ConstantTime => P::SIG_CT_SIZE,
        }
    }
}

/// A Falcon signature.
///
/// This type is generic over the parameter set ([`Falcon512`](crate::Falcon512)
/// or [`Falcon1024`](crate::Falcon1024)) to provide type safety.
pub struct Signature<P: FalconParams> {
    pub(crate) data: Vec<u8>,
    pub(crate) format: SignatureFormat,
    pub(crate) _params: PhantomData<P>,
}

impl<P: FalconParams> Signature<P> {
    /// Create a signature from raw bytes.
    ///
    /// The format is auto-detected from the signature header.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidFormat`] if:
    /// - The signature is too short (< 41 bytes)
    /// - The header doesn't match the expected parameter set
    /// - The header indicates an unknown format
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < 41 {
            return Err(Error::InvalidFormat);
        }

        let header = bytes[0];
        let logn = header & 0x0F;

        if logn as u32 != P::LOGN {
            return Err(Error::InvalidFormat);
        }

        let format = SignatureFormat::from_header(header).ok_or(Error::InvalidFormat)?;

        Ok(Self {
            data: bytes.to_vec(),
            format,
            _params: PhantomData,
        })
    }

    /// Create a signature from raw bytes without validation.
    ///
    /// # Safety
    ///
    /// The caller must ensure that the bytes represent a valid Falcon
    /// signature for the parameter set `P`.
    #[inline]
    pub unsafe fn from_bytes_unchecked(bytes: Vec<u8>, format: SignatureFormat) -> Self {
        Self {
            data: bytes,
            format,
            _params: PhantomData,
        }
    }

    /// Get the raw bytes of this signature.
    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }

    /// Convert the signature into raw bytes.
    #[inline]
    pub fn into_bytes(self) -> Vec<u8> {
        self.data
    }

    /// Get the format of this signature.
    #[inline]
    pub fn format(&self) -> SignatureFormat {
        self.format
    }

    /// Get the length of this signature in bytes.
    #[inline]
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Check if signature is empty (should never be true for valid signatures).
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}

impl<P: FalconParams> Clone for Signature<P> {
    fn clone(&self) -> Self {
        Self {
            data: self.data.clone(),
            format: self.format,
            _params: PhantomData,
        }
    }
}

impl<P: FalconParams> core::fmt::Debug for Signature<P> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Signature")
            .field("format", &self.format)
            .field("len", &self.data.len())
            .finish()
    }
}

impl<P: FalconParams> AsRef<[u8]> for Signature<P> {
    fn as_ref(&self) -> &[u8] {
        &self.data
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Falcon512;

    #[test]
    fn test_signature_format_sizes() {
        assert!(SignatureFormat::Compressed.max_size::<Falcon512>() > 0);
        assert!(SignatureFormat::Padded.max_size::<Falcon512>() > 0);
        assert!(SignatureFormat::ConstantTime.max_size::<Falcon512>() > 0);

        // CT should be largest
        assert!(
            SignatureFormat::ConstantTime.max_size::<Falcon512>()
                > SignatureFormat::Padded.max_size::<Falcon512>()
        );
    }
}
