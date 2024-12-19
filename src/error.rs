use thiserror::Error;

/// Error type for the library.
#[derive(Error, Debug)]
pub enum Error {
    /// Error during formatting.
    #[error("fmt error: {0}")]
    FmtError(#[from] std::fmt::Error),
    /// Error during I/O operations.
    #[error("io error: {0}")]
    IoError(#[from] std::io::Error),
    /// Error during VSSS operations.
    #[error("vsss error: {0}")]
    VsssError(vsss_rs::Error),
    /// Error during postcard serialization/deserialization.
    #[error("Postcard error: {0}")]
    PostcardError(#[from] postcard::Error),
    /// Error during participant initialization.
    #[error("error during participant initialization: {0}")]
    InitializationError(String),
    /// Error during a round of the DKG protocol.
    #[error("round error: {0}")]
    RoundError(String),
}

impl From<vsss_rs::Error> for Error {
    fn from(e: vsss_rs::Error) -> Self {
        Error::VsssError(e)
    }
}

/// Result type for the library.
pub type DkgResult<T> = Result<T, Error>;
