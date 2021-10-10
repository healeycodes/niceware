use ring::{self, rand::SecureRandom};
use std::convert::TryInto;

mod error;
mod words;

const MAX_PASSPHRASE_SIZE: u16 = 1024;

pub fn bytes_to_pass_phrase(bytes: &[u8]) -> Vec<&'static str> {
    if bytes.len() % 2 != 0 {
        panic!("only even-sized byte arrays are supported")
    }
    let _bytes: Vec<u16> = bytes.iter().map(|n| u16::from(*n)).collect();
    let mut words: Vec<&str> = Vec::new();

    for (index, byte) in _bytes.iter().enumerate() {
        if index % 2 == 0 {
            let next = _bytes[index + 1];
            let word_index = byte * 256 + next;
            let word = words::ALL_WORDS[usize::from(word_index)];
            words.push(word);
        }
    }
    words
}

pub fn passphrase_to_bytes(words: &[&str]) -> Result<Vec<u8>, error::UnknownWordError> {
    let mut bytes: Vec<u8> = vec![0; words.len() * 2];

    for (index, word) in words.iter().enumerate() {
        match words::ALL_WORDS.binary_search(&&*word.to_lowercase()) {
            Ok(word_index) => {
                bytes[2 * index] = (word_index / 256) as u8;
                bytes[2 * index + 1] = (word_index % 256) as u8;
            }
            Err(_) => {
                return Err(error::UnknownWordError::new(&format!(
                    "unknown word: {}",
                    word
                )))
            }
        }
    }
    Ok(bytes)
}

pub fn generate_passphrase(num_random_bytes: u16) -> Result<Vec<&'static str>, error::RNGError> {
    if num_random_bytes > MAX_PASSPHRASE_SIZE {
        panic!(
            "num_random_bytes must be between 0 and {}",
            MAX_PASSPHRASE_SIZE
        );
    }

    let mut bytes: Vec<u8> = vec![0; num_random_bytes.try_into().unwrap()];
    let s_rng = ring::rand::SystemRandom::new();
    match s_rng.fill(&mut bytes) {
        Ok(_) => Ok(bytes_to_pass_phrase(&bytes)),
        Err(error) => Err(error::RNGError::new(&format!("{}", error))),
    }
}

#[cfg(test)]
mod tests {
    use crate::{bytes_to_pass_phrase, generate_passphrase, passphrase_to_bytes};

    // generate_passphrase

    #[test]
    fn correct_passphrase_length() {
        assert_eq!(generate_passphrase(2).unwrap().len(), 1);
        assert_eq!(generate_passphrase(0).unwrap().len(), 0);
        assert_eq!(generate_passphrase(20).unwrap().len(), 10);
        assert_eq!(generate_passphrase(512).unwrap().len(), 256);
    }

    #[test]
    #[should_panic(expected = "only even-sized byte arrays are supported")]
    fn panic_odd_passphrase_length_1() {
        let _ = generate_passphrase(1);
    }

    #[test]
    #[should_panic(expected = "only even-sized byte arrays are supported")]
    fn panic_odd_passphrase_length_23() {
        let _ = generate_passphrase(23);
    }

    #[test]
    #[should_panic(expected = "num_random_bytes must be between 0 and 1024")]
    fn panic_passphrase_oob_num_random_bytes_1025() {
        let _ = generate_passphrase(1025);
    }

    // bytes_to_passphrase

    #[test]
    #[should_panic(expected = "only even-sized byte arrays are supported")]
    fn odd_bytes_length() {
        let _ = bytes_to_pass_phrase(&vec![0]);
    }

    #[test]
    fn expected_passphrases() {
        assert_eq!(bytes_to_pass_phrase(&vec![]).len(), 0);
        assert_eq!(bytes_to_pass_phrase(&vec![0, 0]), vec!["a"]);
        assert_eq!(bytes_to_pass_phrase(&vec![255, 255]), vec!["zyzzyva"]);
        assert_eq!(
            bytes_to_pass_phrase(&vec![
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
            passphrase_to_bytes(&vec!["You", "love", "ninetales"])
                .unwrap_err()
                .details,
            "unknown word: ninetales"
        );
    }

    #[test]
    fn expected_bytes() {
        assert_eq!(passphrase_to_bytes(&vec!["A"]).unwrap(), vec![0, 0]);
        assert_eq!(
            passphrase_to_bytes(&vec!["zyzzyva"]).unwrap(),
            vec![255, 255]
        );
        assert_eq!(
            passphrase_to_bytes(
                &"a bioengineering balloted gobbled creneled written depriving zyzzyva"
                    .split(" ")
                    .collect::<Vec<&str>>()
            )
            .unwrap(),
            vec![0, 0, 17, 212, 12, 140, 90, 246, 46, 83, 254, 60, 54, 169, 255, 255]
        );
    }
}
