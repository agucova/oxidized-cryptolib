#![forbid(unsafe_code)]
#![allow(dead_code)]

/*!
    A bespoke implementation of the AES key wrapping algorithm
    as defined in IETF RFC 3394.
    This has NOT been audited or reviewed, and it is not production-ready.
    I couldn't find a crate that worked well and was WASM compatible.
*/

use aes::cipher::{BlockEncrypt, KeyInit};
use aes::Aes256;

// We should eventually ditch generic arrays and start using const generics.
use generic_array::{
    sequence::Concat,
    typenum::{U16, U32, U8},
    GenericArray,
};

type U8x8 = GenericArray<u8, U8>;
type Block = GenericArray<u8, U16>;
type KeyData = GenericArray<u8, U32>;

extern crate hex;

/**
    Initial value from RFC3394 Section 2.2.3.1
    http://www.ietf.org/rfc/rfc3394.txt
*/
const IV_3394: [u8; 8] = [0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6];

fn xor_in_place(a: &mut [u8], b: &[u8]) {
    for (b1, b2) in a.iter_mut().zip(b.iter()) {
        *b1 ^= *b2;
    }
}
// We'll implement only for AES-256 for now.
pub fn wrap_key(plaintext: &[u8], kek: &[u8; 32]) -> Vec<u8> {
    // Ensure that the key is 32 bytes long per AES-256
    assert!(kek.len() == 32);
    // Ensure that the plaintext is a multiple of 64 bits
    assert!(plaintext.len() % 8 == 0);

    // Acquire ownership through copying
    let plaintext = plaintext.to_owned();
    let kek = KeyData::from(kek.to_owned());

    // 1) Initialize variables
    // The 64-bit integrity check register (A)
    let mut integrity_check: U8x8 = U8x8::from(IV_3394);
    // Number of blocks in plaintext (n)
    let n_blocks = plaintext.len() / 8;
    // An array of 64-bit registers of length n (R)
    let mut registers = plaintext;

    // 2) Calculate intermediate values
    // Initialize cipher
    let cipher = Aes256::new(&kek);

    // Wrap the key in 6 * n_blocks steps
    for j in 0..5 {
        for (i, chunk) in registers.chunks_mut(8).enumerate() {
            let t = (n_blocks * j) + i;
            let plaintext_block: U8x8 = *U8x8::from_slice(chunk);

            // B = AES(K, A | R[i])
            let mut iv_block: Block = integrity_check.concat(plaintext_block);
            cipher.encrypt_block(&mut iv_block);

            // MSB(j, W): Return the most significant j bits of W
            // LSB(j, W): Return the least significant j bits of W
            // A = MSB(64, B) ^ t where t = (n*j)+i
            let a = &mut iv_block[0..8];
            xor_in_place(a, &mut t.to_be_bytes());
            integrity_check = *U8x8::from_slice(a);

            // R[i] = LSB(64xw, B)
            chunk.copy_from_slice(&iv_block[8..16]);
            // let hex_integrity_check = hex::encode(&integrity_check);
            // let hex_iv_block = hex::encode(&iv_block);
            // dbg!(t, hex_integrity_check, hex_iv_block);
        }
    }

    // 3) Output the results
    let mut ciphertext = integrity_check.to_vec();
    ciphertext.extend(registers);

    // TODO: Zero out the plaintext and kek buffers

    ciphertext
}

// Test vectors

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    #[test]
    fn test_wrap_key() {
        let kek = hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F");
        let key_data = hex!("00112233445566778899AABBCCDDEEFF");
        let ciphertext = hex!("64E8C3F9CE0F5BA2 63E9777905818A2A 93C8191E7D6E8AE7");

        let wrapped_key = wrap_key(&key_data, &kek);
        assert_eq!(&ciphertext, &wrapped_key.as_slice());
    }
}
