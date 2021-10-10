# rust-niceware

[![Rust](https://github.com/healeycodes/rust-niceware/actions/workflows/rust.yml/badge.svg)](https://github.com/healeycodes/rust-niceware/actions/workflows/rust.yml) [![crates.io v0.2.0](https://img.shields.io/badge/crates.io-v0.2.0-brightgreen)](https://crates.io/crates/rust-niceware)

> My blog post: [Porting Niceware to Rust](https://healeycodes.com/porting-niceware-to-rust)

<br>

_A Rust port of [niceware](https://github.com/diracdeltas/niceware). Sections of this README have been copied from the original project._

This library generates random-yet-memorable passwords. Each word provides 16 bits of entropy, so a useful password requires at least 3 words.

The transformation from bytes to passphrase is reversible.

Because the wordlist is of exactly size 2^16, rust-niceware is also useful for convert cryptographic keys and other sequences of random bytes into human-readable phrases. With rust-niceware, a 128-bit key is equivalent to an 8-word phrase.

Similar to the source, heed this warning:

> WARNING: The wordlist has not been rigorously checked for offensive words. Use at your own risk.

## Sample use cases
- rust-niceware can be used to generate secure, semi-memorable, easy-to-type passphrases. A random 3-5 word phrase in rust-niceware is equivalent to a strong password for authentication to most online services. For instance, `+8svofk0Y1o=` and `bacca cavort west volley` are equally strong (64 bits of randomness).

- rust-niceware can be used to display cryptographic key material in a way that users can easily backup or copy between devices. For instance, the 128-bit random seed used to generate a 256-bit ECC key (~equivalent to a 3072-bit RSA key) is only 8 rust-niceware words. With this 8-word phrase, you can reconstruct the entire public/private key pair.

## Tests

```bash
cargo test
```

## Credits

Rust port:

Code, tests, and docs are either straight-up ported/copied from, or inspired by [niceware](https://github.com/diracdeltas/niceware).

Original:

Niceware was inspired by [Diceware](http://world.std.com/~reinhold/diceware.html). Its wordlist is derived from [the SIL English word list](https://web.archive.org/web/20180803153208/http://www-01.sil.org/linguistics/wordlists/english/). This project is based on [diracdeltas] work on OpenPGP key backup for the Yahoo [End-to-End](https://github.com/yahoo/end-to-end) project.
