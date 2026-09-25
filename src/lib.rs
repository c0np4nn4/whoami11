//! Research implementation of LR-DAS, commitment variants and product-code repair.
//!
//! All protocol operations use public BLS12-381 SRS points. The deterministic setup
//! in [`fixture`] is exclusively a reproducible experiment fixture, not a ceremony.
//! No network deployment or production security claim is provided.
#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod domain;
pub mod fast_polynomial;
pub mod fixture;
pub mod kzg;
pub mod polynomial;
pub mod protocol;
pub mod recovery;
pub mod separation;
pub mod variants;

use std::fmt;
/// A validated input or arithmetic failure. Verification failure is never success.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error(pub String);
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}
impl std::error::Error for Error {}
/// Result used throughout the library.
pub type Result<T> = std::result::Result<T, Error>;
pub(crate) fn require(ok: bool, message: &str) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(Error(message.into()))
    }
}
/// Canonical compressed serialization, with no framing bytes.
pub fn bytes<T: ark_serialize::CanonicalSerialize>(value: &T) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    value
        .serialize_compressed(&mut out)
        .map_err(|e| Error(e.to_string()))?;
    Ok(out)
}
/// Decode exactly one canonical value, including curve/subgroup validation.
pub fn decode<T: ark_serialize::CanonicalDeserialize>(input: &[u8]) -> Result<T> {
    let mut reader = input;
    let value = T::deserialize_compressed(&mut reader).map_err(|e| Error(e.to_string()))?;
    require(reader.is_empty(), "trailing bytes")?;
    Ok(value)
}
