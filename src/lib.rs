//! A Rust port of [niceware](https://github.com/diracdeltas/niceware)
//!
//! Sections of documentation have been copied from the original project.
//! **Important**: `generate_passphrase` is slightly different than original!
//!
//! This library generates random-yet-memorable passwords. Each word provides 16 bits of entropy, so a useful password requires at least 3 words.
//!
//! The transformation from bytes to passphrase is reversible.
//!
//! Because the wordlist is of exactly size 2^16, niceware is also useful for convert cryptographic keys and other sequences of random bytes into human-readable phrases. With niceware, a 128-bit key is equivalent to an 8-word phrase.
//!
//! Similar to the source, heed this warning:
//!
//! > WARNING: The wordlist has not been rigorously checked for offensive words. Use at your own risk.
//!
//! ## Examples
//!
//! ```
//! // Creates 128-bit passphrase which is considered cryptographically secure.
//! println!("Passphrase: {}", niceware::generate_passphrase(8).unwrap().join(" "));
//! ```

pub use error::Error;
use std::convert::TryInto;

mod error;
mod words;

const MAX_PASSPHRASE_WORDS: usize = 512;
const MAX_WORD_LEN: usize = 28;

/// Create word-based passphrase from given bytes.
///
/// Only even-sized slices are supported.
///
/// ## Errors
///
/// This function returns an InvalidSize error if the given slice has an odd number of bytes. It returns an InvalidByte error if the bytes reference invalid words.
pub fn bytes_to_passphrase(bytes: &[u8]) -> Result<Vec<&'static str>, Error> {
    if bytes.len() % 2 != 0 {
        return Err(Error::InvalidSize { size: bytes.len() });
    }

    Ok(bytes
        .chunks_exact(2)
        .map(|pair| {
            let word_index = u16::from_be_bytes(pair.try_into().unwrap());
            words::ALL_WORDS[usize::from(word_index)]
        })
        .collect())
}

/// Decode words into bytes
///
/// This tries to find words in the dictionary and produce the bytes that would have generated
/// them.
///
/// ## Errors
///
/// This function returns an UnknownWord error if a word is not found in the dictionary.
pub fn passphrase_to_bytes(words: &[&str]) -> Result<Vec<u8>, Error> {
    let mut bytes: Vec<u8> = Vec::with_capacity(words.len() * 2);

    for word in words {
        // If a word is longer than maximum then we will definitely not find it.
        // MAX_WORD_LEN is tested below.
        if word.len() > MAX_WORD_LEN {
            return Err(Error::UnknownWord {
                word: word.to_string(),
            });
        }
        // All words are ascii (test below) so we can just do ascii lowercase.
        let word_index = words::ALL_WORDS
            .binary_search(&&word.to_ascii_lowercase()[..])
            .map_err(|_| Error::UnknownWord {
                word: word.to_string(),
            })?;
        bytes.extend(u16::to_be_bytes(word_index.try_into().unwrap()));
    }
    Ok(bytes)
}

/// Convenience funtion to generate a passphrase using OS RNG
///
/// This is a shorthand for generating random bytes, and feeding them to `bytes_to_passphrase`.
///
/// **Important**: As opposed to the original implementation this takes number of words instead of
/// number of bytes. This should be more natural and avoids panics.
///
/// ## Errors
///
/// This function returns an RNGError if the underlying RNG failed to generate bytes. It returns an InvalidSize error if the given size is odd.
pub fn generate_passphrase(num_words: usize) -> Result<Vec<&'static str>, Error> {
    use rand::Rng;

    if num_words > MAX_PASSPHRASE_WORDS {
        return Err(Error::TooManyWords {
            num_words,
            max_words: MAX_PASSPHRASE_WORDS,
        });
    }

    let mut bytes: Vec<u8> = vec![0; usize::from(num_words) * 2];
    let mut s_rng = rand::thread_rng();
    s_rng.try_fill(&mut bytes[..])?;

    bytes_to_passphrase(&bytes)
}

#[cfg(test)]
mod tests {
    use crate::{bytes_to_passphrase, generate_passphrase, passphrase_to_bytes};

    // generate_passphrase

    #[test]
    fn correct_passphrase_length() {
        assert_eq!(generate_passphrase(1).unwrap().len(), 1);
        assert_eq!(generate_passphrase(0).unwrap().len(), 0);
        assert_eq!(generate_passphrase(10).unwrap().len(), 10);
        assert_eq!(generate_passphrase(256).unwrap().len(), 256);
    }

    #[test]
    fn passphrase_oob_num_words_513() {
        assert_eq!(
            generate_passphrase(513).unwrap_err().to_string(),
            "number of words 513 cannot be greater than 512"
        );
    }

    // bytes_to_passphrase

    #[test]
    fn odd_bytes_length() {
        assert_eq!(
            bytes_to_passphrase(&[0]).unwrap_err().to_string(),
            "odd size not supported: 1"
        );
    }

    #[test]
    fn expected_passphrases() {
        assert_eq!(bytes_to_passphrase(&[]).unwrap().len(), 0);
        assert_eq!(bytes_to_passphrase(&[0, 0]).unwrap(), &["a"]);
        assert_eq!(bytes_to_passphrase(&[255, 255]).unwrap(), &["zyzzyva"]);
        assert_eq!(
            bytes_to_passphrase(&[
                0, 0, 17, 212, 12, 140, 90, 246, 46, 83, 254, 60, 54, 169, 255, 255
            ])
            .unwrap(),
            "a bioengineering balloted gobbled creneled written depriving zyzzyva"
                .split(" ")
                .collect::<Vec<&str>>()
        );
    }

    // passphrase_to_bytes

    #[test]
    fn invalid_word() {
        assert_eq!(
            passphrase_to_bytes(&["You", "love", "ninetales"])
                .unwrap_err()
                .to_string(),
            "unknown word: ninetales"
        );
    }

    #[test]
    fn expected_bytes() {
        assert_eq!(passphrase_to_bytes(&["A"]).unwrap(), &[0, 0]);
        assert_eq!(passphrase_to_bytes(&["zyzzyva"]).unwrap(), &[255, 255]);
        assert_eq!(
            passphrase_to_bytes(&[
                "a",
                "bioengineering",
                "balloted",
                "gobbled",
                "creneled",
                "written",
                "depriving",
                "zyzzyva"
            ])
            .unwrap(),
            &[0, 0, 17, 212, 12, 140, 90, 246, 46, 83, 254, 60, 54, 169, 255, 255]
        );
    }

    #[test]
    fn max_word_len() {
        let max_word_len = crate::words::ALL_WORDS
            .iter()
            .copied()
            .map(str::len)
            .max()
            .unwrap();

        assert_eq!(crate::MAX_WORD_LEN, max_word_len);
    }

    #[test]
    fn all_words_are_ascii() {
        // makes sure assumption holds
        assert!(crate::words::ALL_WORDS.iter().copied().all(str::is_ascii));
    }
}
