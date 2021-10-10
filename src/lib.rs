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

use std::fmt;
use std::convert::TryFrom;
use std::iter::FusedIterator;

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
    bytes_to_pass_phrase_iter_from_slice(bytes)
        .collect()
}

fn byte_pair_to_word(pair: [u8; 2]) -> &'static str {
    let word_index = usize::from(pair[0]) * 256 + usize::from(pair[1]);
    words::ALL_WORDS[word_index]
}

/// Represents an iterator of words being converted from bytes.
///
/// This is created by `bytes_to_pass_phrase_iter*` functions and enables you to avoid allocating a
/// `Vec` if you don't need it.
// this is basically just a glorified `std::iter::Map` :)
#[derive(Clone, Debug)]
pub struct BytesToPassphraseIter<T: Iterator<Item=[u8; 2]>> {
    iter: T,
}

impl<T> From<T> for BytesToPassphraseIter<T> where T: Iterator<Item=[u8; 2]> {
    fn from(iter: T) -> Self {
        BytesToPassphraseIter {
            iter,
        }
    }
}


impl<T> BytesToPassphraseIter<T> where T: Iterator<Item=[u8; 2]> + Clone {
    /// Creates a string with words separated by the given separator.
    ///
    /// This function pre-allocates [`String`] so that writing is fast.
    pub fn join(self, separator: impl fmt::Display) -> String {
        use fmt::Write;

        struct Counter(usize);
        impl fmt::Write for Counter {
            fn write_str(&mut self, s: &str) -> fmt::Result {
                self.0 = self.0.saturating_add(s.len());
                Ok(())
            }
        }

        let mut counter = Counter(0);
        write!(&mut counter, "{}", separator).expect("counter never fails");
        let mut string = String::with_capacity(self.clone().bytes_hint(counter.0));
        self.write(&mut string, separator).expect("string allocation never fails");

        string
    }
}

impl<T> BytesToPassphraseIter<T> where T: Iterator<Item=[u8; 2]> {
    /// Calculates the number of bytes occupied by string representation if separated by a
    /// separator of given length.
    ///
    /// This can be used as a size hint for [`String`] or similar types when implementing custom
    /// formatting.
    pub fn bytes_hint(mut self, separator_len: usize) -> usize {
        match self.next() {
            Some(word) => {
                let mut size = word.len();
                for word in self {
                    size = size.saturating_add(word.len()).saturating_add(separator_len);
                }
                size
            },
            None => 0,
        }
    }

    /// Write the words into the `writer` separated by the `separator`.
    ///
    /// This can be used with generic writers avoiding allocations. Note that while this takes
    /// `writer` by value you can still pass a mutable reference.
    pub fn write<W: fmt::Write>(mut self, mut writer: W, separator: impl fmt::Display) -> fmt::Result {
        if let Some(word) = self.next() {
            writer.write_str(word)?;
            for word in self {
                write!(writer, "{}{}", separator, word)?;
            }
        }
        Ok(())
    }
}

impl<T> Iterator for BytesToPassphraseIter<T> where T: Iterator<Item=[u8; 2]> {
    type Item = &'static str;

    fn next(&mut self) -> Option<Self::Item> {
        self.iter.next().map(byte_pair_to_word)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.iter.size_hint()
    }

    // Overriding this can lead to faster code despite `TrustedLen` not being implemented.
    fn collect<B>(self) -> B where B: std::iter::FromIterator<Self::Item> {
        self.iter.map(byte_pair_to_word).collect()
    }
}

impl<T> DoubleEndedIterator for BytesToPassphraseIter<T> where T: Iterator<Item=[u8; 2]> + DoubleEndedIterator {
    fn next_back(&mut self) -> Option<Self::Item> {
        self.iter.next_back().map(byte_pair_to_word)
    }
}

/// Prints the words separated by space or comma and a space (alternative representation).
///
/// As should be obvious from signature this performs a clone of the iterator.
/// This is OK for things like slice iterators because those are cheap but be careful when using
/// something else as it may affect performance.
///
/// Note: if you intend to create a string `join(" ")` is faster than `to_string()`.
impl<T> fmt::Display for BytesToPassphraseIter<T> where T: Iterator<Item=[u8; 2]> + Clone {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let separator = match f.alternate() {
            false => " ",
            true => ", ",
        };

        self.clone().write(f, separator)
    }
}

// correct because we just forward size hint
impl<T> ExactSizeIterator for BytesToPassphraseIter<T> where T: Iterator<Item=[u8; 2]> + ExactSizeIterator {}
impl<T> FusedIterator for BytesToPassphraseIter<T> where T: Iterator<Item=[u8; 2]> + FusedIterator {}

// Ideally we would implement TrustedLen as well but that one is nightly :(
// Hopefully overriding collect can help too.

/// Convert iterator of byte pairs to iterator of words.
///
/// This is similar to [`bytes_to_pass_phrase`] but it operates on iterator instead of slice/vec
/// so it may allow more efficient processing (e.g. avoiding allocations).
///
/// The returned iterator has a bunch of convenience functions that should help fast and easy
/// processing.
pub fn bytes_to_pass_phrase_iter<I>(bytes: I) -> BytesToPassphraseIter<I::IntoIter> where I: IntoIterator<Item=[u8; 2]> {
    BytesToPassphraseIter {
        iter: bytes.into_iter(),
    }
}

/// Convert slice of bytes to iterator of words.
///
/// This is a convenience function that converts slice of bytes to iterator of pairs and passes it
/// to [`bytes_to_pass_phrase_iter`].
///
/// ## Panics
///
/// This function panics if the length of slice is odd.
pub fn bytes_to_pass_phrase_iter_from_slice(bytes: &[u8]) -> BytesToPassphraseIter<impl '_ + Iterator<Item=[u8; 2]> + ExactSizeIterator + Clone + FusedIterator + Send + Sync> {
    if bytes.len() % 2 != 0 {
        panic!("only even-sized byte arrays are supported")
    }
    let iter = bytes
        .chunks_exact(2)
        .map(|pair| *<&[u8; 2]>::try_from(pair).expect("chunks_exact returned invalid slice"));

    bytes_to_pass_phrase_iter(iter)
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
/// This is a shorthand for generating random bytes, and feeding them to [`bytes_to_passphrase`].
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
    use crate::{bytes_to_pass_phrase, bytes_to_pass_phrase_iter_from_slice, generate_passphrase, passphrase_to_bytes};

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

    #[test]
    fn test_passphrase_iter_empty() {
        let bytes = &[];

        assert_eq!(bytes_to_pass_phrase_iter_from_slice(bytes).to_string(), "");
        assert_eq!(format!("{:#}", bytes_to_pass_phrase_iter_from_slice(bytes)), "");
    }

    #[test]
    fn test_passphrase_iter_one() {
        let bytes = &[0, 0];

        assert_eq!(bytes_to_pass_phrase_iter_from_slice(bytes).to_string(), "a");
        assert_eq!(format!("{:#}", bytes_to_pass_phrase_iter_from_slice(bytes)), "a");
    }

    #[test]
    fn test_passphrase_iter_two() {
        let bytes = &[0, 0, 255, 255];

        assert_eq!(bytes_to_pass_phrase_iter_from_slice(bytes).to_string(), "a zyzzyva");
        assert_eq!(format!("{:#}", bytes_to_pass_phrase_iter_from_slice(bytes)), "a, zyzzyva");
    }

    #[test]
    fn test_passphrase_iter_long() {
        let bytes = &[0, 0, 17, 212, 12, 140, 90, 246, 46, 83, 254, 60, 54, 169, 255, 255];

        assert_eq!(bytes_to_pass_phrase_iter_from_slice(bytes).to_string(), "a bioengineering balloted gobbled creneled written depriving zyzzyva");
        assert_eq!(format!("{:#}", bytes_to_pass_phrase_iter_from_slice(bytes)), "a, bioengineering, balloted, gobbled, creneled, written, depriving, zyzzyva");
    }
}
