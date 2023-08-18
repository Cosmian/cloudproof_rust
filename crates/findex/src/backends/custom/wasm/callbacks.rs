use wasm_bindgen::prelude::wasm_bindgen;

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(typescript_type = "() => Promise<uids: Uint8Array[]>")]
    #[derive(Debug)]
    pub type DumpTokens;
}

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(
        typescript_type = "(uids: Uint8Array[]) => Promise<{uid: Uint8Array, value: Uint8Array}[]>"
    )]
    #[derive(Debug, Clone)]
    pub type Fetch;
}

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(
        typescript_type = "(oldValues: {uid: Uint8Array, value: Uint8Array}[], newValues: {uid: \
                           Uint8Array, value: Uint8Array}[]) => Promise<{uid: Uint8Array, value: \
                           Uint8Array}[]>"
    )]
    #[derive(Debug, Clone)]
    pub type Upsert;
}

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(
        typescript_type = "(uidsAndValues: {uid: Uint8Array, value: Uint8Array}[]) => \
                           Promise<void>"
    )]
    #[derive(Debug, Clone)]
    pub type Insert;
}

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(typescript_type = "(uids: Uint8Array[]) => Promise<void>")]
    #[derive(Debug, Clone)]
    pub type Delete;
}
