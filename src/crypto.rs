use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, Key, KeyInit, Nonce};
use argon2::Argon2;
use zeroize::Zeroizing;

pub const SALT_LEN: usize = 16;
pub const NONCE_LEN: usize = 12;
pub const KEY_LEN: usize = 32;

pub fn random(n: usize) -> Vec<u8> {
    let mut buf = vec![0u8; n];
    getrandom::getrandom(&mut buf).expect("system rng unavailable");
    buf
}

pub fn derive_key(passphrase: &str, salt: &[u8]) -> Zeroizing<[u8; KEY_LEN]> {
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    Argon2::default()
        .hash_password_into(passphrase.as_bytes(), salt, key.as_mut_slice())
        .expect("argon2 derivation failed");
    key
}

pub fn seal(key: &[u8], plaintext: &[u8], aad: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let nonce = random(NONCE_LEN);
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .expect("aead encrypt failed");
    (nonce, ciphertext)
}

pub fn open(key: &[u8], nonce: &[u8], ciphertext: &[u8], aad: &[u8]) -> Option<Vec<u8>> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    cipher
        .decrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .ok()
}
