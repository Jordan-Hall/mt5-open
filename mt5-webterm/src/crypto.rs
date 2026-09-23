//! AES-256-CBC and the unused XOR chain from the web-terminal JS.

use aes::Aes256;
use cbc::{Decryptor, Encryptor};
use cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit, block_padding::Pkcs7};

pub const STATIC_KEY: [u8; 32] = [
    0x02, 0xde, 0x02, 0xa1, 0xa6, 0x5c, 0xc7, 0x94, 0x68, 0x4f, 0xcb, 0xea, 0x1e, 0xcb, 0x0f, 0xd7,
    0x4a, 0xe6, 0x57, 0xe4, 0x36, 0x62, 0xc1, 0x1e, 0xee, 0x88, 0x5d, 0x2f, 0xd6, 0x4f, 0x49, 0x64,
];
const ZERO_IV: [u8; 16] = [0; 16];

type Enc = Encryptor<Aes256>;
type Dec = Decryptor<Aes256>;

pub fn aes_encrypt(key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, String> {
    let key: [u8; 32] = key.try_into().map_err(|_| "AES-256 key must be 32 bytes")?;
    Ok(Enc::new((&key).into(), (&ZERO_IV).into()).encrypt_padded_vec_mut::<Pkcs7>(plaintext))
}

pub fn aes_decrypt(key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, String> {
    let key: [u8; 32] = key.try_into().map_err(|_| "AES-256 key must be 32 bytes")?;
    Dec::new((&key).into(), (&ZERO_IV).into())
        .decrypt_padded_vec_mut::<Pkcs7>(ciphertext)
        .map_err(|e| format!("aes decrypt: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_pycryptodome_vector() {
        let pt = b"hello webterm!!";
        let ct = aes_encrypt(&STATIC_KEY, pt).unwrap();
        let hex: String = ct.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(hex, "eb990fda3781c024773389741763ada8");
        assert_eq!(aes_decrypt(&STATIC_KEY, &ct).unwrap(), pt);
    }
}
