use super::*;
// Section: wire functions

#[no_mangle]
pub extern "C" fn wire_gen_keypair(port_: i64) {
    wire_gen_keypair_impl(port_)
}

#[no_mangle]
pub extern "C" fn wire_bin2hex(port_: i64, data: *mut wire_uint_8_list) {
    wire_bin2hex_impl(port_, data)
}

#[no_mangle]
pub extern "C" fn wire_pk_hex__method__KeyPair(port_: i64, that: *mut wire_KeyPair) {
    wire_pk_hex__method__KeyPair_impl(port_, that)
}

#[no_mangle]
pub extern "C" fn wire_sk_hex__method__KeyPair(port_: i64, that: *mut wire_KeyPair) {
    wire_sk_hex__method__KeyPair_impl(port_, that)
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
