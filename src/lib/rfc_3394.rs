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
use zeroize::Zeroize;

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

fn xor<const LEN: usize>(a: &[u8; LEN], b: &[u8; LEN]) -> [u8; LEN]
{
    let c: Vec<u8> =  a.iter()
    .zip(b.iter())
    .map(|(&x1, &x2)| x1 ^ x2)
    .collect();

    c.try_into().unwrap()
}

// We'll implement only for AES-256 for now.
pub fn wrap_key(plaintext: &[u8], kek: &[u8; 32]) -> Vec<u8> {
    // Ensure that the key is 32 bytes long per AES-256
    assert!(kek.len() == 32);
    // Ensure that the plaintext is a multiple of 64 bits
    assert!(plaintext.len() % 8 == 0);

    // Acquire ownership through copying
    let plaintext = plaintext.to_owned();
    let mut kek = KeyData::from(kek.to_owned());

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
    for j in 0..6 {
        for (i, chunk) in registers.chunks_mut(8).enumerate() {
            // i was supposed to start from 1, so we shift
            let t = (n_blocks * j) + (i + 1);
            println!("t: {t}");
            let plaintext_block: U8x8 = *U8x8::from_slice(chunk);

            println!("A (In): {:?}", hex::encode(&integrity_check));
            println!("R (In): {:?}", hex::encode(&plaintext_block));

            // B = AES(K, A | R[i])
            let mut iv_block: Block = integrity_check.concat(plaintext_block);
            cipher.encrypt_block(&mut iv_block);
            // MSB(j, W): Return the most significant j bits of W
            // LSB(j, W): Return the least significant j bits of W
            // A = MSB(64, B) ^ t where t = (n*j)+i
            let a: [u8; 8] = iv_block[0..8].try_into().unwrap();
            println!("A (Enc): {:?}", hex::encode(&a));
            // XOR a with t
            let a = xor(&a, &t.to_be_bytes());

            integrity_check = *U8x8::from_slice(&a);

            // R[i] = LSB(64xw, B)
            println!("A (XorT): {:?}", hex::encode(&a));
            chunk.copy_from_slice(&iv_block[8..16]);
            println!("R (XorT): {:?}", hex::encode(&chunk));
            // let hex_integrity_check = hex::encode(&integrity_check);
            // let hex_iv_block = hex::encode(&iv_block);
        }
    }

    // 3) Output the results
    let mut ciphertext = integrity_check.to_vec();
    ciphertext.extend(registers);

    // Zero out the kek buffer
    kek.zeroize();

    ciphertext
}

// Test vectors

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    #[test]
    fn test_wrap_128_key_with_256_kek() {
        let kek = hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F");
        let key_data = hex!("00112233445566778899AABBCCDDEEFF");
        let ciphertext = hex!("64E8C3F9CE0F5BA2 63E9777905818A2A 93C8191E7D6E8AE7");

        let wrapped_key = wrap_key(&key_data, &kek);
        assert_eq!(&ciphertext, &wrapped_key.as_slice());
    }

    #[test]
    fn test_wrap_192_key_with_256_kek() {
        let kek = hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F");
        let key_data = hex!("00112233445566778899AABBCCDDEEFF0001020304050607");
        let ciphertext = hex!("A8F9BC1612C68B3F F6E6F4FBE30E71E4 769C8B80A32CB895 8CD5D17D6B254DA1");

        let wrapped_key = wrap_key(&key_data, &kek);
        assert_eq!(&ciphertext, &wrapped_key.as_slice());
    }

    #[test]
    fn test_wrap_256_key_with_256_kek() {
        let kek = hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F");
        let key_data = hex!("00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F");
        let ciphertext = hex!("28C9F404C4B810F4 CBCCB35CFB87F826 3F5786E2D80ED326 CBC7F0E71A99F43B FB988B9B7A02DD21");

        let wrapped_key = wrap_key(&key_data, &kek);
        assert_eq!(&ciphertext, &wrapped_key.as_slice());
    }
}
