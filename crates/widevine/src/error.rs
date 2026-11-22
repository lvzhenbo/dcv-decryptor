use std::{borrow::Cow, convert::Infallible};

/// Widevine error
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Error encoding/decoding protobuf
    #[error("protobuf: {0}")]
    Protobuf(#[from] protobuf::Error),
    /// File I/O error
    #[error("i/o: {0}")]
    Io(std::io::Error),
    #[error("rsa: {0}")]
    /// RSA error
    Rsa(#[from] rsa::Error),
    /// Received invalid input
    #[error("invalid input: {0}")]
    InvalidInput(Cow<'static, str>),
    /// Received invalid license
    #[error("invalid license: {0}")]
    InvalidLicense(Cow<'static, str>),
}

impl From<Infallible> for Error {
    fn from(_: Infallible) -> Self {
        unreachable!()
    }
}

impl From<std::io::Error> for Error {
    fn from(value: std::io::Error) -> Self {
        if value.kind() == std::io::ErrorKind::UnexpectedEof {
            Self::InvalidInput("input too short".into())
        } else {
            Self::Io(value)
        }
    }
}
