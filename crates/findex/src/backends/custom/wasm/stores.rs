use cosmian_findex::{TokenToEncryptedValueMap, TokenWithEncryptedValueList, Tokens};
use wasm_bindgen::prelude::wasm_bindgen;

use crate::{
    backends::{
        custom::wasm::callbacks::{Delete, DumpTokens, Fetch, Insert, Upsert},
        BackendError,
    },
    ser_de::wasm_ser_de::{
        edx_lines_to_js_array, js_value_to_edx_lines, js_value_to_uids, uids_to_js_array,
    },
};

/// Structure storing the callback functions passed through the WASM interface.
///
/// Callback functions needed to be implemented for the Entry and Chain tables
/// given the Findex operation:
/// ```txt
///           +-----------+-----------+-----------+-----------+---------------+
///           | `fetch`   | `upsert`  | `insert`  | `delete`  | `dump_tokens` |
/// +---------+-----------+-----------+-----------+-----------+---------------+
/// | search  |  ET + CT  |           |           |           |               |
/// +---------+-----------+-----------+-----------+-----------+---------------+
/// | add     |  ET + CT  |     ET    |    CT     |           |               |
/// +---------+-----------+-----------+-----------+-----------+---------------+
/// | delete  |  ET + CT  |     ET    |    CT     |           |               |
/// +---------+-----------+-----------+-----------+-----------+---------------+
/// | compact |  ET + CT  |           |  ET + CT  |  ET + CT  |       ET      |
/// +---------+-----------+-----------+-----------+-----------+---------------+
/// ```
#[derive(Debug, Default)]
#[wasm_bindgen]
pub struct WasmCallbacks {
    dump_tokens: Option<DumpTokens>,
    fetch: Option<Fetch>,
    upsert: Option<Upsert>,
    insert: Option<Insert>,
    delete: Option<Delete>,
}

#[wasm_bindgen]
impl WasmCallbacks {
    #[wasm_bindgen(constructor)]
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[wasm_bindgen(setter)]
    pub fn set_fetch(&mut self, callback: Fetch) {
        self.fetch = Some(callback);
    }

    #[wasm_bindgen(getter = fetch )]
    #[must_use]
    pub fn get_fetch(&self) -> Option<Fetch> {
        self.fetch.clone()
    }

    #[wasm_bindgen(setter)]
    pub fn set_upsert(&mut self, callback: Upsert) {
        self.upsert = Some(callback);
    }

    #[wasm_bindgen(getter = upsert )]
    #[must_use]
    pub fn get_upsert(&self) -> Option<Upsert> {
        self.upsert.clone()
    }

    #[wasm_bindgen(setter)]
    pub fn set_insert(&mut self, callback: Insert) {
        self.insert = Some(callback);
    }

    #[wasm_bindgen(getter = insert )]
    #[must_use]
    pub fn get_insert(&self) -> Option<Insert> {
        self.insert.clone()
    }

    #[wasm_bindgen(setter)]
    pub fn set_delete(&mut self, callback: Delete) {
        self.delete = Some(callback);
    }

    #[wasm_bindgen(getter = delete )]
    #[must_use]
    pub fn get_delete(&self) -> Option<Delete> {
        self.delete.clone()
    }
}

impl WasmCallbacks {
    pub(crate) async fn dump_tokens(&self) -> Result<Tokens, BackendError> {
        let res = call0!(self, dump_tokens);
        js_value_to_uids(&res)
            .map_err(BackendError::from)
            .map(Into::into)
    }

    pub(crate) async fn fetch<const LENGTH: usize>(
        &self,
        uids: Tokens,
    ) -> Result<TokenWithEncryptedValueList<LENGTH>, BackendError> {
        let js_uids = uids_to_js_array(&uids)?;
        let res = call1!(self, fetch, &js_uids);
        js_value_to_edx_lines(&res)
            .map_err(BackendError::from)
            .map(Into::into)
    }

    pub(crate) async fn upsert<const LENGTH: usize>(
        &self,
        old_values: TokenToEncryptedValueMap<LENGTH>,
        new_values: TokenToEncryptedValueMap<LENGTH>,
    ) -> Result<TokenToEncryptedValueMap<LENGTH>, BackendError> {
        let serialized_old_values = edx_lines_to_js_array(&old_values)?;
        let serialized_new_values = edx_lines_to_js_array(&new_values)?;

        let res = call2!(self, upsert, &serialized_old_values, &serialized_new_values);

        Ok(js_value_to_edx_lines(&res)?.into_iter().collect())
    }

    pub(crate) async fn insert<const LENGTH: usize>(
        &self,
        map: TokenToEncryptedValueMap<LENGTH>,
    ) -> Result<(), BackendError> {
        let serialized_map = edx_lines_to_js_array(&map)?;
        let _ = call1!(self, insert, &serialized_map);
        Ok(())
    }

    pub(crate) async fn delete(&self, uids: Tokens) -> Result<(), BackendError> {
        let serialized_uids = uids_to_js_array(&uids)?;
        let _ = call1!(self, delete, &serialized_uids);
        Ok(())
    }
}
