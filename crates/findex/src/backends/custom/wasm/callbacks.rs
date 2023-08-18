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
    #[derive(Debug)]
    pub type Fetch;
}

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(
        typescript_type = "(oldValues: {uid: Uint8Array, value: Uint8Array}[], newValues: {uid: \
                           Uint8Array, value: Uint8Array}[]) => Promise<{uid: Uint8Array, value: \
                           Uint8Array}[]>"
    )]
    #[derive(Debug)]
    pub type Upsert;
}

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(
        typescript_type = "(uidsAndValues: {uid: Uint8Array, value: Uint8Array}[]) => \
                           Promise<void>"
    )]
    #[derive(Debug)]
    pub type Insert;
}

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(
        typescript_type = "(progressResults: Array<{ keyword: Uint8Array, results: \
                           Array<Uint8Array> }>) => Promise<Boolean>"
    )]
    #[derive(Debug)]
    pub type Delete;
}
