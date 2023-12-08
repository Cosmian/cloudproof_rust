use cosmian_findex::{ENTRY_LENGTH, LINK_LENGTH};
use js_sys::{Function, Promise};
use wasm_bindgen::JsValue;
use wasm_bindgen_futures::JsFuture;

macro_rules! call0 {
    ($obj:ident, $callback:ident) => {{
        if let Some(callback) = &$obj.$callback {
            let this = &$crate::db_interfaces::custom::wasm::JsValue::null();
            let js_function = $crate::db_interfaces::custom::wasm::Function::from(
                $crate::db_interfaces::custom::wasm::JsValue::from(callback),
            );
            let promise =
                $crate::db_interfaces::custom::wasm::Promise::resolve(&js_function.call0(this)?);
            $crate::db_interfaces::custom::wasm::JsFuture::from(promise).await?
        } else {
            return Err(DbInterfaceError::MissingCallback(format!(
                "No attribute `{}` is defined for `self`",
                stringify!($callback)
            )));
        }
    }};
}

macro_rules! call1 {
    ($obj:ident, $callback:ident, $input:expr) => {{
        if let Some(callback) = &$obj.$callback {
            let this = &$crate::db_interfaces::custom::wasm::JsValue::null();
            let js_function = $crate::db_interfaces::custom::wasm::Function::from(
                $crate::db_interfaces::custom::wasm::JsValue::from(callback),
            );
            let promise = $crate::db_interfaces::custom::wasm::Promise::resolve(
                &js_function.call1(this, $input)?,
            );
            $crate::db_interfaces::custom::wasm::JsFuture::from(promise).await?
        } else {
            return Err(DbInterfaceError::MissingCallback(format!(
                "No attribute `{}` is defined for `self`",
                stringify!($callback)
            )));
        }
    }};
}

macro_rules! call2 {
    ($obj:ident, $callback:ident, $input1:expr, $input2:expr) => {{
        if let Some(callback) = &$obj.$callback {
            let this = &$crate::db_interfaces::custom::wasm::JsValue::null();
            let js_function = $crate::db_interfaces::custom::wasm::Function::from(
                $crate::db_interfaces::custom::wasm::JsValue::from(callback),
            );
            let promise = $crate::db_interfaces::custom::wasm::Promise::resolve(
                &js_function.call2(this, $input1, $input2)?,
            );
            $crate::db_interfaces::custom::wasm::JsFuture::from(promise).await?
        } else {
            return Err(DbInterfaceError::MissingCallback(format!(
                "No attribute `{}` is defined for `self`",
                stringify!($callback)
            )));
        }
    }};
}

mod callbacks;
mod stores;

pub use stores::WasmCallbacks;

#[derive(Debug)]
pub struct WasmEntryBackend(WasmCallbacks);

impl_custom_backend!(WasmEntryBackend, WasmCallbacks, ENTRY_LENGTH);

#[derive(Debug)]
pub struct WasmChainBackend(WasmCallbacks);

impl_custom_backend!(WasmChainBackend, WasmCallbacks, LINK_LENGTH);
