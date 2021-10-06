use ring::{self, rand::SecureRandom};
use std::convert::TryInto;

mod words;

const MAX_PASSPHRASE_SIZE: u32 = 1024;

fn main() {
    let phrase = bytes_to_pass_phrase(vec![5, 7]);
    println!("{:?}", phrase);
    println!("{:?}", passphrase_to_bytes(phrase));
}

pub fn bytes_to_pass_phrase(bytes: Vec<u8>) -> Vec<&'static str> {
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
    return words;
}

pub fn passphrase_to_bytes(words: Vec<&str>) -> Result<Vec<u8>, usize> {
    let mut bytes: Vec<u8> = vec![0; words.len() * 2];

    for (index, word) in words.iter().enumerate() {
        let word_index: u16 = words::ALL_WORDS
            .binary_search(&&*word.to_lowercase())?
            .try_into()
            .unwrap();
        bytes[2 * index] = (word_index / 256) as u8;
        bytes[2 * index + 1] = (word_index % 256) as u8;
    }
    Ok(bytes)
}

pub fn generate_passphrase(size: u32) -> Result<Vec<&'static str>, ring::error::Unspecified> {
    if size > MAX_PASSPHRASE_SIZE {
        panic!("size must be between 0 and {}", MAX_PASSPHRASE_SIZE);
    }

    let mut bytes: Vec<u8> = vec![0; size.try_into().unwrap()];
    let s_rng = ring::rand::SystemRandom::new();
    s_rng.fill(&mut bytes)?;

    Ok(bytes_to_pass_phrase(bytes))
}
