// #![cfg_attr(not(test), no_std)]
#![feature(trait_alias)]

mod digest;
mod padding;
mod sha1;
mod sha256;
mod sha512;
mod test;

pub use digest::Digest;
pub use sha1::SHA1Digest;
pub use sha256::{SHA224Digest, SHA256Digest};
pub use sha512::{SHA384Digest, SHA512Digest, SHA512x224Digest, SHA512x256Digest};
