#![cfg_attr(not(test), no_std)]

mod digest;
mod padding;
mod sha1;
mod sha256;
mod test;

pub use digest::Digest;
pub use sha1::SHA1Digest;
pub use sha256::{SHA224Digest, SHA256Digest};
