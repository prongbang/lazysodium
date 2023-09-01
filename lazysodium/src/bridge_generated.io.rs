use super::*;
// Section: wire functions

#[no_mangle]
pub extern "C" fn wire_crypto_kx_keypair(port_: i64, pk_size: usize, sk_size: usize) {
    wire_crypto_kx_keypair_impl(port_, pk_size, sk_size)
}

#[no_mangle]
pub extern "C" fn wire_crypto_box_beforenm(port_: i64, keypair: *mut wire_KeyPair) {
    wire_crypto_box_beforenm_impl(port_, keypair)
}

#[no_mangle]
pub extern "C" fn wire_crypto_box_beforenm_hex(port_: i64, keypair: *mut wire_KeyPair) {
    wire_crypto_box_beforenm_hex_impl(port_, keypair)
}

#[no_mangle]
pub extern "C" fn wire_crypto_kx_client_session_keys(
    port_: i64,
    client_pk: *mut wire_uint_8_list,
    client_sk: *mut wire_uint_8_list,
    server_pk: *mut wire_uint_8_list,
) {
    wire_crypto_kx_client_session_keys_impl(port_, client_pk, client_sk, server_pk)
}

#[no_mangle]
pub extern "C" fn wire_crypto_kx_server_session_keys(
    port_: i64,
    server_pk: *mut wire_uint_8_list,
    server_sk: *mut wire_uint_8_list,
    client_pk: *mut wire_uint_8_list,
) {
    wire_crypto_kx_server_session_keys_impl(port_, server_pk, server_sk, client_pk)
}

#[no_mangle]
pub extern "C" fn wire_crypto_stream_chacha20_xor(
    port_: i64,
    message: *mut wire_uint_8_list,
    nonce: *mut wire_uint_8_list,
    key: *mut wire_uint_8_list,
) {
    wire_crypto_stream_chacha20_xor_impl(port_, message, nonce, key)
}

#[no_mangle]
pub extern "C" fn wire_crypto_aead_chacha20poly1305_encrypt(
    port_: i64,
    message: *mut wire_uint_8_list,
    additional_data: *mut wire_uint_8_list,
    nonce: *mut wire_uint_8_list,
    key: *mut wire_uint_8_list,
) {
    wire_crypto_aead_chacha20poly1305_encrypt_impl(port_, message, additional_data, nonce, key)
}

#[no_mangle]
pub extern "C" fn wire_bin_to_hex(port_: i64, data: *mut wire_uint_8_list) {
    wire_bin_to_hex_impl(port_, data)
}

#[no_mangle]
pub extern "C" fn wire_hex_to_bin(port_: i64, hex: *mut wire_uint_8_list) {
    wire_hex_to_bin_impl(port_, hex)
}

#[no_mangle]
pub extern "C" fn wire_random_bytes_buf(port_: i64, size: usize) {
    wire_random_bytes_buf_impl(port_, size)
}

#[no_mangle]
pub extern "C" fn wire_random_nonce_bytes(port_: i64) {
    wire_random_nonce_bytes_impl(port_)
}

#[no_mangle]
pub extern "C" fn wire_random_nonce_hex(port_: i64) {
    wire_random_nonce_hex_impl(port_)
}

// Section: allocate functions

#[no_mangle]
pub extern "C" fn new_box_autoadd_key_pair_0() -> *mut wire_KeyPair {
    support::new_leak_box_ptr(wire_KeyPair::new_with_null_ptr())
}

#[no_mangle]
pub extern "C" fn new_uint_8_list_0(len: i32) -> *mut wire_uint_8_list {
    let ans = wire_uint_8_list {
        ptr: support::new_leak_vec_ptr(Default::default(), len),
        len,
    };
    support::new_leak_box_ptr(ans)
}

// Section: related functions

// Section: impl Wire2Api

impl Wire2Api<String> for *mut wire_uint_8_list {
    fn wire2api(self) -> String {
        let vec: Vec<u8> = self.wire2api();
        String::from_utf8_lossy(&vec).into_owned()
    }
}
impl Wire2Api<KeyPair> for *mut wire_KeyPair {
    fn wire2api(self) -> KeyPair {
        let wrap = unsafe { support::box_from_leak_ptr(self) };
        Wire2Api::<KeyPair>::wire2api(*wrap).into()
    }
}
impl Wire2Api<KeyPair> for wire_KeyPair {
    fn wire2api(self) -> KeyPair {
        KeyPair {
            pk: self.pk.wire2api(),
            sk: self.sk.wire2api(),
        }
    }
}

impl Wire2Api<Vec<u8>> for *mut wire_uint_8_list {
    fn wire2api(self) -> Vec<u8> {
        unsafe {
            let wrap = support::box_from_leak_ptr(self);
            support::vec_from_leak_ptr(wrap.ptr, wrap.len)
        }
    }
}

// Section: wire structs

#[repr(C)]
#[derive(Clone)]
pub struct wire_KeyPair {
    pk: *mut wire_uint_8_list,
    sk: *mut wire_uint_8_list,
}

#[repr(C)]
#[derive(Clone)]
pub struct wire_uint_8_list {
    ptr: *mut u8,
    len: i32,
}

// Section: impl NewWithNullPtr

pub trait NewWithNullPtr {
    fn new_with_null_ptr() -> Self;
}

impl<T> NewWithNullPtr for *mut T {
    fn new_with_null_ptr() -> Self {
        std::ptr::null_mut()
    }
}

impl NewWithNullPtr for wire_KeyPair {
    fn new_with_null_ptr() -> Self {
        Self {
            pk: core::ptr::null_mut(),
            sk: core::ptr::null_mut(),
        }
    }
}

impl Default for wire_KeyPair {
    fn default() -> Self {
        Self::new_with_null_ptr()
    }
}

// Section: sync execution mode utility

#[no_mangle]
pub extern "C" fn free_WireSyncReturn(ptr: support::WireSyncReturn) {
    unsafe {
        let _ = support::box_from_leak_ptr(ptr);
    };
}
