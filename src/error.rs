use thiserror::Error;

/// Error type for the library.
#[derive(Error, Debug)]
pub enum Error {
    /// Error during formatting.
    #[error("fmt error: {0}")]
    Fmt(#[from] std::fmt::Error),
    /// Error during I/O operations.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    /// Error during VSSS operations.
    #[error("vsss error: {0}")]
    Vsss(vsss_rs::Error),
    /// Error during postcard serialization/deserialization.
    #[error("Postcard error: {0}")]
    Postcard(#[from] postcard::Error),
    /// Error during participant initialization.
    #[error("error during participant initialization: {0}")]
    Initialization(String),
    /// Error during a round of the DKG protocol.
    #[error("round error: {0}")]
    Round(String),
    /// Publicly Verifiable Secret Sharing Verification Error
    #[error("publicly verifiable secret sharing error: {0}")]
    Pvss(String),
}

impl From<vsss_rs::Error> for Error {
    fn from(e: vsss_rs::Error) -> Self {
        Error::Vsss(e)
    }
}

/// Result type for the library.
pub type DkgResult<T> = Result<T, Error>;
