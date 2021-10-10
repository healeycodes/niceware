use std::{error::Error, fmt};

/// Error returned when a word is not found in dictionary.
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

/// Error returned when an RNG fails to generate entropy.
#[derive(Debug)]
pub struct RNGError {
    error: rand::Error,
}
impl RNGError {
    pub(crate) fn new(error: rand::Error) -> RNGError {
        RNGError {
            error,
        }
    }
}
impl fmt::Display for RNGError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("failed to generate entropy for passphrase")
    }
}

impl Error for RNGError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.error)
    }
}
