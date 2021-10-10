use std::{error::Error, fmt};

#[derive(Debug)]
pub struct UnknownWordError {
    pub(crate) details: String,
}

impl UnknownWordError {
    pub(crate) fn new(msg: &str) -> UnknownWordError {
        UnknownWordError {
            details: msg.to_string(),
        }
    }
}

impl fmt::Display for UnknownWordError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.details)
    }
}

impl Error for UnknownWordError {
    fn description(&self) -> &str {
        &self.details
    }
}

#[derive(Debug)]
pub struct RNGError {
    pub(crate) details: String,
}
impl RNGError {
    pub(crate) fn new(msg: &str) -> RNGError {
        RNGError {
            details: msg.to_string(),
        }
    }
}
impl fmt::Display for RNGError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.details)
    }
}

impl Error for RNGError {
    fn description(&self) -> &str {
        &self.details
    }
}
