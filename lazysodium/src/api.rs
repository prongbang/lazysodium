use std::ptr;
use libc::{c_char, c_uchar};
use libsodium_sys::{crypto_aead_aes256gcm_KEYBYTES, crypto_aead_chacha20poly1305_ABYTES, crypto_aead_chacha20poly1305_ietf_KEYBYTES, crypto_aead_chacha20poly1305_IETF_KEYBYTES, crypto_aead_chacha20poly1305_KEYBYTES, crypto_aead_chacha20poly1305_NPUBBYTES, crypto_aead_chacha20poly1305_NSECBYTES, crypto_aead_xchacha20poly1305_ietf_KEYBYTES, crypto_auth_hmacsha512_KEYBYTES, crypto_box_BEFORENMBYTES, crypto_box_curve25519xsalsa20poly1305_PUBLICKEYBYTES, crypto_box_curve25519xsalsa20poly1305_SECRETKEYBYTES, crypto_box_PUBLICKEYBYTES, crypto_box_SECRETKEYBYTES, crypto_kx_PUBLICKEYBYTES, crypto_kx_SECRETKEYBYTES, crypto_kx_SESSIONKEYBYTES, crypto_secretbox_KEYBYTES, crypto_secretbox_NONCEBYTES, crypto_secretbox_xchacha20poly1305_KEYBYTES, crypto_secretbox_xchacha20poly1305_MACBYTES, crypto_secretbox_xchacha20poly1305_NONCEBYTES, crypto_secretstream_xchacha20poly1305_KEYBYTES, crypto_stream_chacha20_ietf_KEYBYTES, crypto_stream_chacha20_ietf_NONCEBYTES, crypto_stream_chacha20_KEYBYTES, crypto_stream_chacha20_NONCEBYTES, crypto_stream_KEYBYTES, crypto_stream_NONCEBYTES, crypto_stream_xchacha20_KEYBYTES, crypto_stream_xchacha20_NONCEBYTES, crypto_stream_xsalsa20_KEYBYTES};

pub const CRYPTO_KX_PK_BYTES: usize = crypto_kx_PUBLICKEYBYTES as usize;
pub const CRYPTO_KX_SK_BYTES: usize = crypto_kx_SECRETKEYBYTES as usize;
pub const CRYPTO_KX_PK_HEX: usize = CRYPTO_KX_PK_BYTES * 2;
pub const CRYPTO_KX_SK_HEX: usize = CRYPTO_KX_SK_BYTES * 2;
pub const CRYPTO_KX_SESSION_KEY_BYTES: usize = crypto_kx_SESSIONKEYBYTES as usize;
pub const CRYPTO_KX_SECRET_KEY_BYTES: usize = crypto_kx_SECRETKEYBYTES as usize;
pub const CRYPTO_BOX_PK_KEY_BYTES: usize = crypto_box_PUBLICKEYBYTES as usize;
pub const CRYPTO_BOX_SK_KEY_BYTES: usize = crypto_box_SECRETKEYBYTES as usize;
pub const CRYPTO_AEAD_CHACHA20POLY1305_KEY_BYTES: usize = crypto_aead_chacha20poly1305_KEYBYTES as usize;
pub const CRYPTO_AEAD_CHACHA20POLY1305_ABYTES: usize = crypto_aead_chacha20poly1305_ABYTES as usize;
pub const CRYPTO_AEAD_CHACHA20POLY1305_NSEC_BYTES: usize = crypto_aead_chacha20poly1305_NSECBYTES as usize;
pub const CRYPTO_AEAD_CHACHA20POLY1305_NPUB_BYTES: usize = crypto_aead_chacha20poly1305_NPUBBYTES as usize;
pub const CRYPTO_AEAD_CHACHA20POLY1305_IETF_KEY_BYTES: usize = crypto_aead_chacha20poly1305_ietf_KEYBYTES as usize;
pub const CRYPTO_AEAD_XCHACHA20POLY1305_IETF_KEY_BYTES: usize = crypto_aead_xchacha20poly1305_ietf_KEYBYTES as usize;
pub const CRYPTO_STREAM_XSALSA20_KEY_BYTES: usize = crypto_stream_xsalsa20_KEYBYTES as usize;
pub const CRYPTO_BOX_CURVE25519XSALSA20POLY1305_PK_BYTES: usize = crypto_box_curve25519xsalsa20poly1305_PUBLICKEYBYTES as usize;
pub const CRYPTO_BOX_CURVE25519XSALSA20POLY1305_SK_BYTES: usize = crypto_box_curve25519xsalsa20poly1305_SECRETKEYBYTES as usize;
pub const CRYPTO_NONCE_BYTES: usize = 24;
pub const CRYPTO_NONCE_HEX: usize = 48;
pub const CRYPTO_BOX_BEFORE_NM_BYTES: usize = crypto_box_BEFORENMBYTES as usize;
pub const CRYPTO_SECRET_BOX_NONCE_BYTES: usize = crypto_secretbox_NONCEBYTES as usize;
pub const CRYPTO_SECRETBOX_KEY_BYTES: usize = crypto_secretbox_KEYBYTES as usize;
pub const CRYPTO_STREAM_CHACHA20_KEY_BYTES: usize = crypto_stream_chacha20_KEYBYTES as usize;
pub const CRYPTO_STREAM_CHACHA20_NONCE_BYTES: usize = crypto_stream_chacha20_NONCEBYTES as usize;
pub const CRYPTO_STREAM_CHACHA20_IETF_KEY_BYTES: usize = crypto_stream_chacha20_ietf_KEYBYTES as usize;
pub const CRYPTO_STREAM_CHACHA20_IETF_NONCE_BYTES: usize = crypto_stream_chacha20_ietf_NONCEBYTES as usize;
pub const CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_KEY_BYTES: usize = crypto_secretstream_xchacha20poly1305_KEYBYTES as usize;
pub const CRYPTO_STREAM_KEY_BYTES: usize = crypto_stream_KEYBYTES as usize;
pub const CRYPTO_STREAM_NONCE_BYTES: usize = crypto_stream_NONCEBYTES as usize;
pub const CRYPTO_STREAM_XCHACHA20_KEY_BYTES: usize = crypto_stream_xchacha20_KEYBYTES as usize;
pub const CRYPTO_STREAM_XCHACHA20_NONCE_BYTES: usize = crypto_stream_xchacha20_NONCEBYTES as usize;
pub const CRYPTO_SECRETBOX_XCHACHA20POLY1305_KEY_BYTES: usize = crypto_secretbox_xchacha20poly1305_KEYBYTES as usize;
pub const CRYPTO_SECRETBOX_XCHACHA20POLY1305_NONCE_BYTES: usize = crypto_secretbox_xchacha20poly1305_NONCEBYTES as usize;
pub const CRYPTO_SECRETBOX_XCHACHA20POLY1305_MAC_BYTES: usize = crypto_secretbox_xchacha20poly1305_MACBYTES as usize;

#[derive(Debug, Clone)]
pub struct KeyPair {
    pub pk: Vec<u8>,
    pub sk: Vec<u8>,
}

#[derive(Debug)]
pub struct SessionKey {
    pub rx: Vec<u8>,
    pub tx: Vec<u8>,
}

pub fn crypto_kx_keypair(pk_size: usize, sk_size: usize) -> KeyPair {
    let mut pk: Vec<u8> = vec![0; pk_size];
    let mut sk: Vec<u8> = vec![0; sk_size];

    unsafe {
        libsodium_sys::crypto_kx_keypair(pk.as_mut_ptr(), sk.as_mut_ptr());
    }

    KeyPair {
        pk: pk.to_vec(),
        sk: sk.to_vec(),
    }
}

pub fn crypto_box_before_nm(keypair: KeyPair) -> Vec<u8> {
    // Create a mutable vector to store the shared secret key (precomputed)
    let mut shared_key: Vec<u8> = vec![0; CRYPTO_BOX_BEFORE_NM_BYTES];

    // Call crypto_box_beforenm to compute the shared secret key
    let result = unsafe {
        libsodium_sys::crypto_box_beforenm(
            shared_key.as_mut_ptr() as *mut c_uchar,
            keypair.pk.as_ptr() as *const c_uchar,
            keypair.sk.as_ptr() as *const c_uchar,
        )
    };

    if result == 0 {
        // The shared secret key has been computed successfully
        shared_key
    } else {
        // An error occurred during key computation; return an empty vector
        vec![]
    }
}

pub fn crypto_box_beforenm_hex(keypair: KeyPair) -> String {
    let byte = crypto_box_before_nm(keypair);
    let hex = bin_to_hex(byte);
    hex
}

pub fn crypto_kx_client_session_keys(
    client_keypair: KeyPair,
    server_pk: Vec<u8>,
) -> SessionKey {
    // Create mutable vectors to store the session keys
    let len = client_keypair.sk.len();
    let mut rx: Vec<u8> = vec![0; len];
    let mut tx: Vec<u8> = vec![0; len];

    // Call crypto_kx_client_session_keys to compute the session keys
    let result = unsafe {
        libsodium_sys::crypto_kx_client_session_keys(
            rx.as_mut_ptr() as *mut c_uchar,
            tx.as_mut_ptr() as *mut c_uchar,
            client_keypair.pk.as_ptr() as *const c_uchar,
            client_keypair.sk.as_ptr() as *const c_uchar,
            server_pk.as_ptr() as *const c_uchar,
        )
    };

    if result == 0 {
        // The session keys have been computed successfully
        SessionKey { rx, tx }
    } else {
        // An error occurred during key computation; return empty vectors
        SessionKey { rx: vec![], tx: vec![] }
    }
}

pub fn crypto_kx_server_session_keys(
    server_keypair: KeyPair,
    client_pk: Vec<u8>,
) -> SessionKey {
    // Create mutable vectors to store the session keys
    let len = server_keypair.sk.len();
    let mut rx: Vec<u8> = vec![0; len];
    let mut tx: Vec<u8> = vec![0; len];

    // Call crypto_kx_client_session_keys to compute the session keys
    let result = unsafe {
        libsodium_sys::crypto_kx_server_session_keys(
            rx.as_mut_ptr() as *mut c_uchar,
            tx.as_mut_ptr() as *mut c_uchar,
            server_keypair.pk.as_ptr() as *const c_uchar,
            server_keypair.sk.as_ptr() as *const c_uchar,
            client_pk.as_ptr() as *const c_uchar,
        )
    };

    if result == 0 {
        // The session keys have been computed successfully
        SessionKey { rx, tx }
    } else {
        // An error occurred during key computation; return empty vectors
        SessionKey { rx: vec![], tx: vec![] }
    }
}

pub fn crypto_stream_chacha20_xor(
    message: Vec<u8>,
    nonce: Vec<u8>,
    key: Vec<u8>,
) -> Vec<u8> {
    let message_size = message.len();
    let mut output: Vec<u8> = vec![0; message_size];
    // Call crypto_stream_chacha20_xor to encrypt the message
    let result = unsafe {
        libsodium_sys::crypto_stream_chacha20_xor(
            output.as_mut_ptr(),
            message.as_ptr(),
            message.len() as libc::c_ulonglong,
            nonce.as_ptr(),
            key.as_ptr(),
        )
    };

    if result == 0 {
        return output;
    }

    return vec![];
}

pub fn crypto_aead_chacha20poly1305_encrypt(
    message: Vec<u8>,
    nonce: Vec<u8>,
    key: Vec<u8>,
    additional_data: Vec<u8>,
) -> Vec<u8> {
    // Determine the size of the ciphertext, which is the size of the message plus the overhead
    let ciphertext_size = message.len() + CRYPTO_AEAD_CHACHA20POLY1305_ABYTES;

    // Create a mutable vector to hold the ciphertext
    let mut ciphertext: Vec<u8> = vec![0; ciphertext_size];

    // Call crypto_aead_chacha20poly1305_encrypt to encrypt the message
    let result = unsafe {
        libsodium_sys::crypto_aead_chacha20poly1305_encrypt(
            ciphertext.as_mut_ptr(),
            ptr::null_mut(), // clen_p (output length) is not needed
            message.as_ptr(),
            message.len() as libc::c_ulonglong,
            additional_data.as_ptr(),
            additional_data.len() as libc::c_ulonglong,
            ptr::null(), // nsec (not needed)
            nonce.as_ptr(),
            key.as_ptr(),
        )
    };

    if result != 0 {
        // An error occurred during encryption; return an empty vector
        return vec![];
    }

    ciphertext
}

pub fn crypto_aead_chacha20poly1305_decrypt(
    ciphertext: Vec<u8>,
    nonce: Vec<u8>,
    key: Vec<u8>,
    additional_data: Vec<u8>,
) -> Vec<u8> {
    // Determine the maximum size of the plaintext, which is the size of the ciphertext minus the overhead
    let plaintext_max_size = ciphertext.len() - CRYPTO_AEAD_CHACHA20POLY1305_ABYTES;

    // Create a mutable vector to hold the plaintext with the maximum possible size
    let mut plaintext: Vec<u8> = vec![0; plaintext_max_size];

    let mut mlen = 0u64;

    // Call crypto_aead_chacha20poly1305_decrypt to decrypt the ciphertext
    let result = unsafe {
        libsodium_sys::crypto_aead_chacha20poly1305_decrypt(
            plaintext.as_mut_ptr(),
            &mut mlen,
            ptr::null_mut(), // nsec (output not needed)
            ciphertext.as_ptr(),
            ciphertext.len() as libc::c_ulonglong,
            additional_data.as_ptr(),
            additional_data.len() as libc::c_ulonglong,
            nonce.as_ptr(),
            key.as_ptr(),
        )
    };

    if result == 0 {
        // Decryption was successful; resize the plaintext vector to the actual length
        plaintext.resize(mlen as usize, 0);
    }

    plaintext
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
    let hex = hex_output.as_ptr();
    let hex_string = unsafe { std::ffi::CStr::from_ptr(hex) }
        .to_string_lossy()
        .into_owned();

    hex_string
}

pub fn crypto_secretbox_xchacha20poly1305_easy(
    message: Vec<u8>,
    nonce: Vec<u8>,
    key: Vec<u8>,
) -> Vec<u8> {
    // Determine the size of the ciphertext, which is the size of the message plus the overhead
    let ciphertext_size = message.len();

    // Create a mutable vector to hold the ciphertext
    let mut ciphertext: Vec<u8> = vec![0; ciphertext_size];

    // Call crypto_secretbox_xchacha20poly1305_easy to encrypt the message
    let result = unsafe {
        libsodium_sys::crypto_secretbox_xchacha20poly1305_easy(
            ciphertext.as_mut_ptr(),
            message.as_ptr(),
            message.len() as libc::c_ulonglong,
            nonce.as_ptr(),
            key.as_ptr(),
        )
    };

    if result == 0 {
        // Encryption was successful
        ciphertext
    } else {
        // An error occurred during encryption; return an empty vector
        vec![]
    }
}


pub fn hex_to_bin(hex: String) -> Vec<u8> {
    // Determine the expected maximum length of the binary output
    let max_binary_len = hex.len() / 2; // Two hexadecimal characters represent one byte

    // Create a mutable vector to hold the binary data
    let mut binary_data: Vec<c_uchar> = vec![0; max_binary_len];

    // Declare variables for optional parameters
    let ignore = ptr::null(); // No characters to ignore
    let mut bin_len: usize = 0;
    let mut hex_end: *const c_char = ptr::null();

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
    let bytes = random_bytes_buf(CRYPTO_NONCE_BYTES);
    return bytes;
}

pub fn random_nonce_hex() -> String {
    let bytes = random_bytes_buf(CRYPTO_NONCE_BYTES);
    let hex = bin_to_hex(bytes);
    return hex;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gen_keypair() {
        let keypair = crypto_kx_keypair(CRYPTO_KX_PK_BYTES, CRYPTO_KX_SK_BYTES);
        println!("{:?}", &keypair.pk.len());
        println!("{:?}", &keypair.sk.len());
        println!("{:?}", &keypair);
    }

    #[test]
    fn test_bin_to_hex() {
        let keypair = crypto_kx_keypair(CRYPTO_KX_PK_BYTES, CRYPTO_KX_SK_BYTES);
        let pk = keypair.pk;
        let sk = keypair.sk;
        let pk_hex = bin_to_hex(pk);
        let sk_hex = bin_to_hex(sk);
        println!("{:?}", &pk_hex);
        println!("{:?}", &sk_hex);
        assert_eq!(pk_hex.len(), CRYPTO_KX_PK_HEX);
        assert_eq!(sk_hex.len(), CRYPTO_KX_SK_HEX);
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
    fn test_crypto_box_beforenm() {
        let client_keypair = crypto_kx_keypair(CRYPTO_KX_PK_BYTES, CRYPTO_KX_SK_BYTES);
        let server_keypair = crypto_kx_keypair(CRYPTO_KX_PK_BYTES, CRYPTO_KX_SK_BYTES);
        let kx_server_shared_key = KeyPair {
            pk: client_keypair.pk,
            sk: server_keypair.sk,
        };
        let kx_client_shared_key = KeyPair {
            pk: server_keypair.pk,
            sk: client_keypair.sk,
        };
        let kx_server_shared_key_bytes = crypto_box_before_nm(kx_server_shared_key);
        let kx_client_shared_key_bytes = crypto_box_before_nm(kx_client_shared_key);
        let kx_server_shared_key_hex = bin_to_hex(kx_server_shared_key_bytes);
        let kx_client_shared_key_hex = bin_to_hex(kx_client_shared_key_bytes);
        println!("{:?}", &kx_server_shared_key_hex);
        println!("{:?}", &kx_client_shared_key_hex);
        assert_eq!(kx_server_shared_key_hex, kx_client_shared_key_hex);
    }

    #[test]
    fn test_crypto_kx_client_and_server_session_keys() {
        let client_keypair = crypto_kx_keypair(CRYPTO_KX_PK_BYTES, CRYPTO_KX_SK_BYTES);
        let server_keypair = crypto_kx_keypair(CRYPTO_KX_PK_BYTES, CRYPTO_KX_SK_BYTES);

        let kx_client_session_key = crypto_kx_client_session_keys(
            client_keypair.clone(),
            server_keypair.pk.clone(),
        );
        let kx_server_session_key = crypto_kx_server_session_keys(
            server_keypair.clone(),
            client_keypair.pk.clone(),
        );
        let server_rx_hex = bin_to_hex(kx_client_session_key.rx);
        let server_tx_hex = bin_to_hex(kx_client_session_key.tx);
        let client_rx_hex = bin_to_hex(kx_server_session_key.rx);
        let client_tx_hex = bin_to_hex(kx_server_session_key.tx);
        println!("{}", server_rx_hex);
        println!("{}", server_tx_hex);
        println!("{}", client_rx_hex);
        println!("{}", client_tx_hex);
    }

    #[test]
    fn test_random_bytes_buf() {
        let bytes = random_bytes_buf(CRYPTO_NONCE_BYTES);
        let nonce_hex = bin_to_hex(bytes.clone());
        println!("{:?}", &bytes.len());
        println!("{:?}", &bytes);
        println!("{:?}", &nonce_hex);
        println!("{:?}", &nonce_hex.len());
        assert_eq!(bytes.len(), CRYPTO_NONCE_BYTES)
    }

    #[test]
    fn test_random_nonce_bytes() {
        let bytes = random_nonce_bytes();
        println!("{:?}", &bytes.len());
        println!("{:?}", &bytes);
        assert_eq!(bytes.len(), CRYPTO_NONCE_BYTES)
    }

    #[test]
    fn test_random_nonce_hex() {
        let hex = random_nonce_hex();
        println!("{:?}", &hex.len());
        println!("{:?}", &hex);
        assert_eq!(hex.len(), CRYPTO_NONCE_HEX);
    }

    #[test]
    fn test_crypto_aead_chacha20poly1305_encrypt_and_decrypt() {
        let nonce_byte = random_bytes_buf(CRYPTO_AEAD_CHACHA20POLY1305_NPUB_BYTES);
        let client_keypair = crypto_kx_keypair(CRYPTO_AEAD_CHACHA20POLY1305_KEY_BYTES, CRYPTO_AEAD_CHACHA20POLY1305_KEY_BYTES);
        let server_keypair = crypto_kx_keypair(CRYPTO_AEAD_CHACHA20POLY1305_KEY_BYTES, CRYPTO_AEAD_CHACHA20POLY1305_KEY_BYTES);
        let kx_server_shared_key = KeyPair {
            pk: client_keypair.pk,
            sk: server_keypair.sk,
        };
        let kx_client_shared_key = KeyPair {
            pk: server_keypair.pk,
            sk: client_keypair.sk,
        };
        let kx_server_shared_key_bytes = crypto_box_before_nm(kx_server_shared_key);
        let kx_client_shared_key_bytes = crypto_box_before_nm(kx_client_shared_key);

        let message = "Lazysodium";
        let message_bytes = message.as_bytes().to_vec();
        let additional_data: Vec<u8> = vec![];

        // Encrypt
        let cipher_bytes = crypto_aead_chacha20poly1305_encrypt(
            message_bytes.clone(),
            nonce_byte.clone(),
            kx_server_shared_key_bytes,
            additional_data.clone(),
        );
        let ciphertext = bin_to_hex(cipher_bytes.clone());
        println!("{}", ciphertext);

        // Decrypt
        let plain_bytes = crypto_aead_chacha20poly1305_decrypt(
            cipher_bytes.clone(),
            nonce_byte.clone(),
            kx_client_shared_key_bytes,
            additional_data.clone(),
        );
        let plaintext = String::from_utf8(plain_bytes).unwrap();
        println!("{}", &plaintext);
        assert_eq!(plaintext, message);
    }

    #[test]
    fn test_crypto_stream_chacha20_xor_encrypt_and_decrypt() {
        let nonce_hex = "4e1600e28682d0226f9fcb50f82fd23c498ce4c4a738e2de".to_string();
        let nonce = hex_to_bin(nonce_hex);
        let server_shared_key_hex = "232d2af723a8947bd536f9766139b4cd2ea79074693b6e2a60445a6996ce45ed".to_string();
        let client_shared_key_hex = "232d2af723a8947bd536f9766139b4cd2ea79074693b6e2a60445a6996ce45ed".to_string();
        let server_shared_key = hex_to_bin(server_shared_key_hex);
        let client_shared_key = hex_to_bin(client_shared_key_hex);

        let message = "Lazysodium";
        let message_byte = message.as_bytes().to_vec();

        // Encrypt
        let cipher_byte = crypto_stream_chacha20_xor(message_byte, nonce.clone(), server_shared_key);
        let cipher_hex = bin_to_hex(cipher_byte.to_vec());
        println!("{}", &cipher_hex);
        assert_eq!(cipher_hex, "8abd28d7a98c233cf8a8");

        // Decrypt
        let plain_byte = crypto_stream_chacha20_xor(cipher_byte, nonce.clone(), client_shared_key);
        let plaintext = String::from_utf8(plain_byte).unwrap();
        println!("{}", &plaintext);
        assert_eq!(plaintext, message);
    }
}