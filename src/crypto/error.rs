//! Cryptographic errors

#[derive(Debug)]
pub enum CryptoError {
    KeygenError,
    SignError,
    VerifyError,
}