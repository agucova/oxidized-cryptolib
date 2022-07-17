#![forbid(unsafe_code)]
#![allow(dead_code)]

/*!
    This is a pure Rust implementation of the AES key wrapping algorithm
    as defined in [IETF RFC3394](https://datatracker.ietf.org/doc/html/rfc3394).

    The implementation relies on the [`aes`](https://crates.io/crates/aes) crate from RustCrypto.

    This crate has NOT been audited and it's provided as-is.
*/

use aes::cipher::{BlockEncrypt, KeyInit, BlockDecrypt};
use aes::Aes256;
use zeroize::Zeroize;
use thiserror::Error;

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
extern crate test;

/**
    IV from RFC3394 Section 2.2.3.1
    https://datatracker.ietf.org/doc/html/rfc3394#section-2.2.3.1
*/
const IV_3394: [u8; 8] = [0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6];

#[derive(Error, Debug)]
pub enum WrapError {
    #[error("The plaintext length is not a multiple of 64 bits per RFC3394.")]
    InvalidPlaintextLength,
}

/// Wraps a key using the AES key wrapping algorithm defined in RFC3394.
/// The key (plaintext) is wrapped using the key encryption key (KEK)
/// through successive rounds of AES encryption.
/// For now this function only supports AES-256.
pub fn wrap_key(plaintext: &[u8], kek: &[u8; 32]) -> Result<Vec<u8>, WrapError> {

    // Ensure that the plaintext is a multiple of 64 bits
    if plaintext.len() % 8 != 0 {
        return Err(WrapError::InvalidPlaintextLength);
    }

    // Acquire ownership through copying
    let plaintext = plaintext.to_owned();
    let mut kek = KeyData::from(kek.to_owned());

    // 1) Initialize variables
    let n_blocks = plaintext.len() / 8;
    // The 64-bit integrity check register (A)
    let mut integrity_check: U8x8 = U8x8::from(IV_3394);
    // An array of 64-bit registers of length n (R)
    let mut registers = plaintext;

    // 2) Calculate intermediate values
    let cipher = Aes256::new(&kek);

    // Wrap the key in 6 * n_blocks steps
    for j in 0..6 {
        for (i, chunk) in registers.chunks_mut(8).enumerate() {
            // i was supposed to start from 1, so we shift
            let t = (n_blocks * j) + (i + 1);
            let plaintext_block: U8x8 = *U8x8::from_slice(chunk);

            // B = AES(K, A | R[i])
            let mut iv_block: Block = integrity_check.concat(plaintext_block);
            cipher.encrypt_block(&mut iv_block);

            // A = MSB(64, B) ^ t where t = (n*j)+i
            // Because we're using BE, we can just get the first 64 bits
            let a = &mut iv_block[0..8];

            // XOR with t
            for i in 0..8 {
                a[i] ^= t.to_be_bytes()[i];
            }
            // Overwrite integrity_check with a
            integrity_check.copy_from_slice(a);

            // R[i] = LSB(64xw, B)
            chunk.copy_from_slice(&iv_block[8..16]);
        }
    }

    // 3) Output the results
    let mut ciphertext = integrity_check.to_vec();
    ciphertext.extend(registers);

    // Zero out the kek buffer
    kek.zeroize();

    Ok(ciphertext)
}

#[derive(Error, Debug)]
pub enum UnwrapError {
    #[error("The ciphertext length is not a multiple of 64 bits per RFC3394.")]
    InvalidCiphertextLength,
    #[error("The integrity check failed.")]
    InvalidIntegrityCheck,
}

/// Unwraps a key using the AES key wrapping algorithm defined in RFC3394.
/// The ciphertext is unwrapped using the key encryption key (KEK)
/// through successive rounds of AES decryption.
///
/// In the case that the given kek is not the correct key,
/// it is expected that the integrity check will fail (`InvalidIntegrityCheck`).
pub fn unwrap_key(ciphertext: &[u8], kek: &[u8; 32]) -> Result<Vec<u8>, UnwrapError> {
    // Ensure that the ciphertext is a multiple of 64 bits
    if ciphertext.len() % 8 != 0 {
        return Err(UnwrapError::InvalidCiphertextLength);
    }

    // Acquire ownership through copying
    let mut kek = KeyData::from(kek.to_owned());

    // 1) Initialize variables
    // We need to substract the IV block
    let n_blocks = (ciphertext.len() / 8) - 1;
    // The 64-bit integrity check register (A) initialized from the first 8 bytes of ciphertext
    let mut integrity_check = U8x8::from_slice(&ciphertext[0..8]).to_owned();
    // An array of 64-bit registers of length n (R) initialized from the rest of the ciphertext
    let mut registers = ciphertext[8..].to_owned();

    // 2) Calculate intermediate values
    let cipher = Aes256::new(&kek);

    // Unwrap the key in 6 * n_blocks steps
    for j in (0..6).rev() {
        for (i, chunk) in registers.chunks_mut(8).enumerate().rev() {
            // i was supposed to start from 1, so we shift
            let t = (n_blocks * j) + (i + 1);
            let ciphertext_block: U8x8 = *U8x8::from_slice(chunk);

            // B = AES-1(K, (A ^ t) | R[i]) where t = n*j+i
            let a = &mut integrity_check.clone();
            for i in 0..8 {
                a[i] ^= t.to_be_bytes()[i];
            }
            let mut iv_block: Block = a.concat(ciphertext_block);
            cipher.decrypt_block(&mut iv_block);

            // A = MSB(64, B)
            // Because we're using BE, we can just get the first 64 bits
            integrity_check.copy_from_slice(&iv_block[0..8]);

            // R[i] = LSB(64, B)
            chunk.copy_from_slice(&iv_block[8..16]);
        }
    }

    // 3) Output the results

    // Zero out the kek buffer
    kek.zeroize();

    // Check if the integrity check register matches the IV
    if !integrity_check.eq(&U8x8::from(IV_3394)) {
        return Err(UnwrapError::InvalidIntegrityCheck);
    }

    // Get the plaintext from the registers
    Ok(registers)
}



#[cfg(test)]
mod tests {
    //! Test vectors

    use super::*;
    use test::Bencher;
    use hex_literal::hex;

    #[test]
    #[should_panic(expected = "InvalidPlaintextLength")]
    fn test_wrap_invalid_key_256_kek() {
        let kek = hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F");
        let key_data = hex!("00112233445566778899AABBCCDDEEFFF123");

        // Wrap
        wrap_key(&key_data, &kek).unwrap();
    }

    #[test]
    fn test_wrap_128_key_with_256_kek() {
        let kek = hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F");
        let key_data = hex!("00112233445566778899AABBCCDDEEFF");
        let ciphertext = hex!("64E8C3F9CE0F5BA2 63E9777905818A2A 93C8191E7D6E8AE7");

        // Wrap
        let wrapped_key = wrap_key(&key_data, &kek).unwrap();
        assert_eq!(&ciphertext, &wrapped_key.as_slice());
    }

    #[test]
    fn test_unwrap_128_key_with_256_kek() {
        let kek = hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F");
        let key_data = hex!("00112233445566778899AABBCCDDEEFF");
        let ciphertext = hex!("64E8C3F9CE0F5BA2 63E9777905818A2A 93C8191E7D6E8AE7");

        // Unwrap
        let unwrapped_key = unwrap_key(&ciphertext, &kek).unwrap();
        assert_eq!(&key_data, &unwrapped_key.as_slice());
    }

    #[test]
    fn test_wrap_192_key_with_256_kek() {
        let kek = hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F");
        let key_data = hex!("00112233445566778899AABBCCDDEEFF0001020304050607");
        let ciphertext = hex!("A8F9BC1612C68B3F F6E6F4FBE30E71E4 769C8B80A32CB895 8CD5D17D6B254DA1");

        // Wrap
        let wrapped_key = wrap_key(&key_data, &kek).unwrap();
        assert_eq!(&ciphertext, &wrapped_key.as_slice());
    }

    #[test]
    #[should_panic(expected = "InvalidCiphertextLength")]
    fn test_unwrap_invalid_key_with_256_kek() {
        let kek = hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F");
        let key_data = hex!("00112233445566778899AABBCCDDEEFF0001020304050607");
        let ciphertext = hex!("A8F9BC1612C68B3F F6E6F4FBE30E");

        // Unwrap
        let unwrapped_key = unwrap_key(&ciphertext, &kek).unwrap();
        assert_eq!(&key_data, &unwrapped_key.as_slice());
    }

    #[test]
    #[should_panic(expected = "InvalidIntegrityCheck")]
    fn test_unwrap_192_key_with_wrong_kek() {
        let kek = hex!("36b0144a13d0b5c1950c435762ff47789ab64258763f6f980f66dc00c11697cd");
        let key_data = hex!("00112233445566778899AABBCCDDEEFF0001020304050607");
        let ciphertext = hex!("A8F9BC1612C68B3F F6E6F4FBE30E71E4 769C8B80A32CB895 8CD5D17D6B254DA1");

        // Unwrap
        let unwrapped_key = unwrap_key(&ciphertext, &kek).unwrap();
        assert_eq!(&key_data, &unwrapped_key.as_slice());
    }


    #[test]
    fn test_unwrap_192_key_with_256_kek() {
        let kek = hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F");
        let key_data = hex!("00112233445566778899AABBCCDDEEFF0001020304050607");
        let ciphertext = hex!("A8F9BC1612C68B3F F6E6F4FBE30E71E4 769C8B80A32CB895 8CD5D17D6B254DA1");

        // Unwrap
        let unwrapped_key = unwrap_key(&ciphertext, &kek).unwrap();
        assert_eq!(&key_data, &unwrapped_key.as_slice());
    }

    #[test]
    fn test_wrap_256_key_with_256_kek() {
        let kek = hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F");
        let key_data = hex!("00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F");
        let ciphertext = hex!("28C9F404C4B810F4 CBCCB35CFB87F826 3F5786E2D80ED326 CBC7F0E71A99F43B FB988B9B7A02DD21");

        let wrapped_key = wrap_key(&key_data, &kek).unwrap();
        assert_eq!(&ciphertext, &wrapped_key.as_slice());
    }

    #[test]
    fn test_unwrap_256_key_with_256_kek() {
        let kek = hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F");
        let key_data = hex!("00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F");
        let ciphertext = hex!("28C9F404C4B810F4 CBCCB35CFB87F826 3F5786E2D80ED326 CBC7F0E71A99F43B FB988B9B7A02DD21");

        let unwrapped_key = unwrap_key(&ciphertext, &kek).unwrap();
        assert_eq!(&key_data, &unwrapped_key.as_slice());
    }

    #[bench]
    fn bench_wrap_256_key_with_256_kek(b: &mut Bencher) {
        let kek = hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F");
        let key_data = hex!("00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F");

        b.iter(|| wrap_key(&key_data, &kek).unwrap());
    }


}
