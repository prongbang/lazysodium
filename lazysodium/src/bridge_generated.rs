#![allow(
    non_camel_case_types,
    unused,
    clippy::redundant_closure,
    clippy::useless_conversion,
    clippy::unit_arg,
    clippy::double_parens,
    non_snake_case,
    clippy::too_many_arguments
)]
// AUTO GENERATED FILE, DO NOT EDIT.
// Generated by `flutter_rust_bridge`@ 1.81.0.

use crate::api::*;
use core::panic::UnwindSafe;
use flutter_rust_bridge::rust2dart::IntoIntoDart;
use flutter_rust_bridge::*;
use std::ffi::c_void;
use std::sync::Arc;

// Section: imports

// Section: wire functions

fn wire_gen_keypair_impl(port_: MessagePort) {
    FLUTTER_RUST_BRIDGE_HANDLER.wrap::<_, _, _, KeyPair>(
        WrapInfo {
            debug_name: "gen_keypair",
            port: Some(port_),
            mode: FfiCallMode::Normal,
        },
        move || move |task_callback| Ok(crypto_kx_keypair()),
    )
}
fn wire_bin_to_hex_impl(port_: MessagePort, data: impl Wire2Api<Vec<u8>> + UnwindSafe) {
    FLUTTER_RUST_BRIDGE_HANDLER.wrap::<_, _, _, String>(
        WrapInfo {
            debug_name: "bin_to_hex",
            port: Some(port_),
            mode: FfiCallMode::Normal,
        },
        move || {
            let api_data = data.wire2api();
            move |task_callback| Ok(bin_to_hex(api_data))
        },
    )
}
fn wire_hex_to_bin_impl(port_: MessagePort, hex: impl Wire2Api<String> + UnwindSafe) {
    FLUTTER_RUST_BRIDGE_HANDLER.wrap::<_, _, _, Vec<u8>>(
        WrapInfo {
            debug_name: "hex_to_bin",
            port: Some(port_),
            mode: FfiCallMode::Normal,
        },
        move || {
            let api_hex = hex.wire2api();
            move |task_callback| Ok(hex_to_bin(api_hex))
        },
    )
}
// Section: wrapper structs

// Section: static checks

// Section: allocate functions

// Section: related functions

// Section: impl Wire2Api

pub trait Wire2Api<T> {
    fn wire2api(self) -> T;
}

impl<T, S> Wire2Api<Option<T>> for *mut S
where
    *mut S: Wire2Api<T>,
{
    fn wire2api(self) -> Option<T> {
        (!self.is_null()).then(|| self.wire2api())
    }
}

impl Wire2Api<u8> for u8 {
    fn wire2api(self) -> u8 {
        self
    }
}

// Section: impl IntoDart

impl support::IntoDart for KeyPair {
    fn into_dart(self) -> support::DartAbi {
        vec![
            self.pk.into_into_dart().into_dart(),
            self.sk.into_into_dart().into_dart(),
        ]
        .into_dart()
    }
}
impl support::IntoDartExceptPrimitive for KeyPair {}
impl rust2dart::IntoIntoDart<KeyPair> for KeyPair {
    fn into_into_dart(self) -> Self {
        self
    }
}

// Section: executor

support::lazy_static! {
    pub static ref FLUTTER_RUST_BRIDGE_HANDLER: support::DefaultHandler = Default::default();
}

#[cfg(not(target_family = "wasm"))]
#[path = "bridge_generated.io.rs"]
mod io;
#[cfg(not(target_family = "wasm"))]
pub use io::*;
