use libc::{c_char, c_uchar};
use libsodium_sys::{crypto_kx_PUBLICKEYBYTES, crypto_kx_SECRETKEYBYTES};

pub const KX_PK_BYTES: usize = crypto_kx_PUBLICKEYBYTES as usize;
pub const KX_SK_BYTES: usize = crypto_kx_SECRETKEYBYTES as usize;
pub const KX_PK_HEX_BYTES: usize = KX_PK_BYTES * 2;
pub const KX_SK_HEX_BYTES: usize = KX_SK_BYTES * 2;

pub type PublicKey = [u8; KX_PK_BYTES];
pub type SecretKey = [u8; KX_SK_BYTES];

#[derive(Debug)]
pub struct KeyPair {
    pub pk: Vec<u8>,
    pub sk: Vec<u8>,
}

impl KeyPair {
    pub fn pk_hex(&self) -> String {
        let pk_bytes = self.pk.to_vec();
        return bin2hex(pk_bytes);
    }

    pub fn sk_hex(&self) -> String {
        let sk_bytes = self.sk.to_vec();
        return bin2hex(sk_bytes);
    }
}

pub fn gen_keypair() -> KeyPair {
    let mut pk: [u8; KX_PK_BYTES] = [0; KX_PK_BYTES];
    let mut sk: [u8; KX_SK_BYTES] = [0; KX_SK_BYTES];

    unsafe {
        libsodium_sys::crypto_kx_keypair(pk.as_mut_ptr(), sk.as_mut_ptr());
    }

    KeyPair {
        pk: pk.to_vec(),
        sk: sk.to_vec(),
    }
}

pub fn bin2hex(data: Vec<u8>) -> String {
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

fn vec_to_string(mut hex_output: Vec<i8>) -> String {
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
        println!("{:?}", &keypair.pk_hex());
        println!("{:?}", &keypair.sk_hex());
        println!("{:?}", &keypair);
    }

    #[test]
    fn test_bin2hex() {
        let result = gen_keypair();
        let pk = result.pk.to_vec();
        let sk = result.sk.to_vec();
        let pk_hex = bin2hex(pk);
        let sk_hex = bin2hex(sk);
        println!("{:?}", &pk_hex);
        println!("{:?}", &sk_hex);
        println!("{:?}", &pk_hex.len());
        println!("{:?}", &sk_hex.len());
    }
}