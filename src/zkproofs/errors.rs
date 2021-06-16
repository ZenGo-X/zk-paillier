use std::error::Error;
use std::fmt;

#[derive(Debug, Clone)]
pub struct IncorrectProof;

impl fmt::Display for IncorrectProof {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "given proof doesn't match a statement")
    }
}

impl Error for IncorrectProof {}
