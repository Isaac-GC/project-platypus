pub mod zip;
pub mod axml;
pub mod arsc;
pub mod split;

use std::fmt;

#[derive(Debug)]
pub enum ApkError {
    Io(std::io::Error),
    Zip(String),
    Parse(String),
    NotFound(String),
}

impl fmt::Display for ApkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ApkError::Io(e)       => write!(f, "IO error: {}", e),
            ApkError::Zip(s)      => write!(f, "ZIP error: {}", s),
            ApkError::Parse(s)    => write!(f, "Parse error: {}", s),
            ApkError::NotFound(s) => write!(f, "Not found: {}", s),
        }
    }
}

impl std::error::Error for ApkError {}

impl From<std::io::Error> for ApkError {
    fn from(e: std::io::Error) -> Self {
        ApkError::Io(e)
    }
}

impl From<::zip::result::ZipError> for ApkError {
    fn from(e: ::zip::result::ZipError) -> Self {
        ApkError::Zip(e.to_string())
    }
}
