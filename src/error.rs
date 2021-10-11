use std::{error, fmt};

#[derive(Debug)]
pub enum Error {
    /// Error returned when an array size is of odd length.
    InvalidSize { size: usize },
    /// Error returned when a word is not found in dictionary.
    UnknownWord { word: String },
    /// Error returned when a word count is greater than the maximum allowed.
    TooManyWords { num_words: usize, max_words: usize },
    /// Error returned when an RNG fails to generate entropy.
    RNGError { inner: rand::Error },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::InvalidSize { size } => write!(f, "odd size not supported: {}", size),
            Error::UnknownWord { word } => write!(f, "unknown word: {}", word),
            Error::TooManyWords {
                num_words,
                max_words,
            } => {
                write!(
                    f,
                    "number of words {} cannot be greater than {}",
                    num_words, max_words
                )
            }
            Error::RNGError { inner } => {
                write!(f, "failed to generate entropy for passphrase: {}", inner)
            }
        }
    }
}

impl error::Error for Error {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            Error::RNGError { ref inner } => Some(inner),
            _ => None,
        }
    }
}

impl From<rand::Error> for Error {
    fn from(e: rand::Error) -> Self {
        Error::RNGError { inner: e }
    }
}
