use libc::{c_char, c_uchar};
use libsodium_sys::{crypto_kx_PUBLICKEYBYTES, crypto_kx_SECRETKEYBYTES};

pub const CRYPTO_KX_PK_BYTE_SIZE: usize = crypto_kx_PUBLICKEYBYTES as usize;
pub const CRYPTO_KX_SK_BYTE_SIZE: usize = crypto_kx_SECRETKEYBYTES as usize;
pub const CRYPTO_KX_PK_HEX_SIZE: usize = CRYPTO_KX_PK_BYTE_SIZE * 2;
pub const CRYPTO_KX_SK_HEX_SIZE: usize = CRYPTO_KX_SK_BYTE_SIZE * 2;
pub const CRYPTO_NONCE_BYTE_SIZE: usize = 24;
pub const CRYPTO_NONCE_HEX_SIZE: usize = 48;

#[derive(Debug)]
pub struct KeyPair {
    pub pk: Vec<u8>,
    pub sk: Vec<u8>,
}

pub fn gen_keypair() -> KeyPair {
    let mut pk: [u8; CRYPTO_KX_PK_BYTE_SIZE] = [0; CRYPTO_KX_PK_BYTE_SIZE];
    let mut sk: [u8; CRYPTO_KX_SK_BYTE_SIZE] = [0; CRYPTO_KX_SK_BYTE_SIZE];

    unsafe {
        libsodium_sys::crypto_kx_keypair(pk.as_mut_ptr(), sk.as_mut_ptr());
    }

    KeyPair {
        pk: pk.to_vec(),
        sk: sk.to_vec(),
    }
}

pub fn bin_to_hex(data: Vec<u8>) -> String {
    let len = data.len();
    let mut hex_output: Vec<c_char> = vec![0; 2 * len + 1];

    unsafe {
        libsodium_sys::sodium_bin2hex(
            hex_output.as_mut_ptr(),
            hex_output.len(),
            data.as_ptr(),
            data.len(),
        );
    }

    // Convert the C string to a Rust string
    let hex_string = vec_to_string(hex_output);

    hex_string
}

pub fn hex_to_bin(hex: String) -> Vec<u8> {
    // Determine the expected maximum length of the binary output
    let max_binary_len = hex.len() / 2; // Two hexadecimal characters represent one byte

    // Create a mutable vector to hold the binary data
    let mut binary_data: Vec<c_uchar> = vec![0; max_binary_len];

    // Declare variables for optional parameters
    let ignore = std::ptr::null(); // No characters to ignore
    let mut bin_len: usize = 0;
    let mut hex_end: *const c_char = std::ptr::null();

    // Convert the hexadecimal string to binary
    let result = unsafe {
        libsodium_sys::sodium_hex2bin(
            binary_data.as_mut_ptr(),
            max_binary_len,
            hex.as_ptr() as *const c_char,
            hex.len(),
            ignore,
            &mut bin_len as *mut usize,
            &mut hex_end as *mut *const c_char,
        )
    };

    // Check if the conversion was successful
    if result == 0 {
        // The conversion was successful, and bin_len contains the actual length of the binary data
        binary_data.resize(bin_len, 0);
    }

    binary_data
}

pub fn random_bytes_buf(size: usize) -> Vec<u8> {
    // Create a mutable buffer of the specified size to hold the random bytes
    let mut buffer: Vec<c_uchar> = vec![0; size];

    // Call randombytes_buf to fill the buffer with random bytes
    unsafe {
        libsodium_sys::randombytes_buf(buffer.as_mut_ptr() as *mut libc::c_void, size);
    }

    // Convert the buffer to Vec<u8>
    let random_bytes: Vec<u8> = buffer.into_iter().map(|byte| byte as u8).collect();

    random_bytes
}

pub fn random_nonce_bytes() -> Vec<u8> {
    let bytes = random_bytes_buf(CRYPTO_NONCE_BYTE_SIZE);
    return bytes;
}

pub fn random_nonce_hex() -> String {
    let bytes = random_bytes_buf(CRYPTO_NONCE_BYTE_SIZE);
    let hex = bin_to_hex(bytes);
    return hex;
}

fn vec_to_string(hex_output: Vec<i8>) -> String {
    unsafe { std::ffi::CStr::from_ptr(hex_output.as_ptr()) }
        .to_string_lossy()
        .into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gen_keypair() {
        let keypair = gen_keypair();
        println!("{:?}", &keypair.pk.len());
        println!("{:?}", &keypair.sk.len());
        println!("{:?}", &keypair);
    }

    #[test]
    fn test_bin_to_hex() {
        let result = gen_keypair();
        let pk = result.pk;
        let sk = result.sk;
        let pk_hex = bin_to_hex(pk);
        let sk_hex = bin_to_hex(sk);
        println!("{:?}", &pk_hex);
        println!("{:?}", &sk_hex);
        assert_eq!(pk_hex.len(), CRYPTO_KX_PK_HEX_SIZE);
        assert_eq!(sk_hex.len(), CRYPTO_KX_SK_HEX_SIZE);
    }

    #[test]
    fn test_hex_to_bin() {
        let pk_hex = "1be470dad3f6d448c2a16272e4aac228f76e64870694e8569423d7518bf74c26";
        let sk_hex = "284151a4157da7206525358e385ac59769d1db4ebfe977c3dfc8e8f411fe3ebc";
        let pk_bytes = hex_to_bin(pk_hex.to_string());
        let sk_bytes = hex_to_bin(sk_hex.to_string());
        let actual_pk_hex = bin_to_hex(pk_bytes.clone());
        let actual_sk_hex = bin_to_hex(sk_bytes.clone());
        println!("{:?}", &pk_bytes);
        println!("{:?}", &sk_bytes);
        println!("{:?}", &actual_pk_hex);
        println!("{:?}", &actual_sk_hex);
        assert_eq!(actual_pk_hex, pk_hex);
        assert_eq!(actual_sk_hex, sk_hex);
    }

    #[test]
    fn test_random_bytes_buf() {
        let bytes = random_bytes_buf(CRYPTO_NONCE_BYTE_SIZE);
        let nonce_hex = bin_to_hex(bytes.clone());
        println!("{:?}", &bytes.len());
        println!("{:?}", &bytes);
        println!("{:?}", &nonce_hex);
        println!("{:?}", &nonce_hex.len());
        assert_eq!(bytes.len(), CRYPTO_NONCE_BYTE_SIZE)
    }

    #[test]
    fn test_random_nonce_bytes() {
        let bytes = random_nonce_bytes();
        println!("{:?}", &bytes.len());
        println!("{:?}", &bytes);
        assert_eq!(bytes.len(), CRYPTO_NONCE_BYTE_SIZE)
    }

    #[test]
    fn test_random_nonce_hex() {
        let hex = random_nonce_hex();
        println!("{:?}", &hex.len());
        println!("{:?}", &hex);
        assert_eq!(hex.len(), CRYPTO_NONCE_HEX_SIZE)
    }
}