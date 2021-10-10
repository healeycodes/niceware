use std::{error::Error, fmt};

#[derive(Debug)]
pub struct UnknownWordError {
    word: Box<str>,
}

impl UnknownWordError {
    pub(crate) fn new(word: &str) -> UnknownWordError {
        UnknownWordError {
            word: word.into()
        }
    }
}

impl fmt::Display for UnknownWordError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "unknown word: {}", self.word)
    }
}

impl Error for UnknownWordError {}

#[derive(Debug)]
pub struct RNGError {
    error: ring::error::Unspecified,
}
impl RNGError {
    pub(crate) fn new(error: ring::error::Unspecified) -> RNGError {
        RNGError {
            error,
        }
    }
}
impl fmt::Display for RNGError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "failed to generate entropy for passphrase: {}", self.error)
    }
}

impl Error for RNGError {}
