//! A Rust port of [niceware](https://github.com/diracdeltas/niceware)
//!
//! Sections of documentation have been copied from the original project.
//! **Important**: `generate_passphrase` is slightly different than original!
//!
//! This library generates random-yet-memorable passwords. Each word provides 16 bits of entropy, so a useful password requires at least 3 words.
//!
//! The transformation from bytes to passphrase is reversible.
//!
//! Because the wordlist is of exactly size 2^16, rust-niceware is also useful for convert cryptographic keys and other sequences of random bytes into human-readable phrases. With rust-niceware, a 128-bit key is equivalent to an 8-word phrase.
//!
//! Similar to the source, heed this warning:
//!
//! > WARNING: The wordlist has not been rigorously checked for offensive words. Use at your own risk.
//!
//! ## Examples
//!
//! ```
//! // Creates 128-bit passphrase which is considered cryptographically secure.
//! println!("Passphrase: {}", rust_niceware::generate_passphrase(8).unwrap().join(" "));
//! ```

pub use error::{UnknownWordError, RNGError};

mod error;
mod words;

const MAX_PASSPHRASE_WORDS: u16 = 512;
const MAX_WORD_LEN: usize = 28;

/// Create word-based passphrase from given bytes.
///
/// Only even-sized slices are supported.
///
/// ## Panics
///
/// This function panics if the length of slice is odd.
pub fn bytes_to_pass_phrase(bytes: &[u8]) -> Vec<&'static str> {
    if bytes.len() % 2 != 0 {
        panic!("only even-sized byte arrays are supported")
    }
    bytes.chunks_exact(2).map(|pair| {
        let word_index = usize::from(pair[0]) * 256 + usize::from(pair[1]);
        words::ALL_WORDS[word_index]
    })
    .collect()
}

/// Decode words into bytes
///
/// This tries to find words in the dictionary and produce the bytes that would have generated
/// them.
///
/// ## Errors
///
/// This currently returns an error if a word is not found and returns no other errors.
pub fn passphrase_to_bytes(words: &[&str]) -> Result<Vec<u8>, UnknownWordError> {
    let mut bytes: Vec<u8> = Vec::with_capacity(words.len() * 2);
    let mut word_buffer = [0; MAX_WORD_LEN];

    for word in words {
        // If a word is longer than maximum then we will definitely not find it.
        // MAX_WORD_LEN is tested below.
        if word.len() > MAX_WORD_LEN {
            return Err(UnknownWordError::new(word));
        }
        // All words are ascii (test below) so we can just do ascii lowercase.
        for (src, dst) in word.bytes().zip(&mut word_buffer) {
            *dst = src.to_ascii_lowercase();
        }
        let word_lowercase = &word_buffer[..word.len()];

        let word_index = words::ALL_WORDS
            .binary_search_by_key(&word_lowercase, |word| word.as_bytes())
            .map_err(|_| UnknownWordError::new(word))?;

        // Casting is safe because we have 2^16 words so the index can not possibly be greater than
        // 2^16 - 1. 2^16 - 1 / 256 == 255
        bytes.push((word_index / 256) as u8);
        // Casting is safe because x % 256 is always at most 255
        bytes.push((word_index % 256) as u8);
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
/// Returns error if the underlying RNG failed to generate bytes.
pub fn generate_passphrase(num_words: u16) -> Result<Vec<&'static str>, RNGError> {
    use rand::Rng;

    if num_words > MAX_PASSPHRASE_WORDS {
        panic!(
            "num_words must be between 0 and {}",
            MAX_PASSPHRASE_WORDS
        );
    }

    let mut bytes: Vec<u8> = vec![0; usize::from(num_words) * 2];
    let mut s_rng = rand::thread_rng();
    s_rng.try_fill(&mut *bytes).map_err(RNGError::new)?;

    Ok(bytes_to_pass_phrase(&bytes))
}

#[cfg(test)]
mod tests {
    use crate::{bytes_to_pass_phrase, generate_passphrase, passphrase_to_bytes};

    // generate_passphrase

    #[test]
    fn correct_passphrase_length() {
        assert_eq!(generate_passphrase(1).unwrap().len(), 1);
        assert_eq!(generate_passphrase(0).unwrap().len(), 0);
        assert_eq!(generate_passphrase(10).unwrap().len(), 10);
        assert_eq!(generate_passphrase(256).unwrap().len(), 256);
    }

    #[test]
    #[should_panic(expected = "num_words must be between 0 and 512")]
    fn panic_passphrase_oob_num_words_513() {
        let _ = generate_passphrase(513);
    }

    // bytes_to_passphrase

    #[test]
    #[should_panic(expected = "only even-sized byte arrays are supported")]
    fn odd_bytes_length() {
        let _ = bytes_to_pass_phrase(&[0]);
    }

    #[test]
    fn expected_passphrases() {
        assert_eq!(bytes_to_pass_phrase(&[]).len(), 0);
        assert_eq!(bytes_to_pass_phrase(&[0, 0]), &["a"]);
        assert_eq!(bytes_to_pass_phrase(&[255, 255]), &["zyzzyva"]);
        assert_eq!(
            bytes_to_pass_phrase(&[
                0, 0, 17, 212, 12, 140, 90, 246, 46, 83, 254, 60, 54, 169, 255, 255
            ]),
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
        assert_eq!(
            passphrase_to_bytes(&["zyzzyva"]).unwrap(),
            &[255, 255]
        );
        assert_eq!(
            passphrase_to_bytes(
                &["a", "bioengineering", "balloted", "gobbled", "creneled", "written", "depriving", "zyzzyva"]
            )
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
