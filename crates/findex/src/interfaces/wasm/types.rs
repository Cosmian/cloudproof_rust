//! This module defines the signature of the Findex WASM callbacks.

use std::collections::{HashMap, HashSet};

use cosmian_findex::{IndexedValue, Keyword, KeywordToDataMap, Keywords, Location};
use js_sys::{Array, JsString, Object, Reflect, Uint8Array};
use wasm_bindgen::{prelude::wasm_bindgen, JsCast, JsValue};

use super::WasmError;
use crate::ser_de::wasm_ser_de::get_bytes_from_object_property;

#[wasm_bindgen]
extern "C" {
    /// Findex search result type.
    ///
    /// See [`FindexSearch::search()`](crate::core::FindexSearch::search).
    #[wasm_bindgen(typescript_type = "Array<{ keyword: Uint8Array, results: Array<Uint8Array> }>")]
    pub type SearchResults;
}

impl TryFrom<&KeywordToDataMap> for SearchResults {
    type Error = WasmError;

    fn try_from(results: &KeywordToDataMap) -> Result<Self, Self::Error> {
        let array = Array::new_with_length(results.len() as u32);
        for (i, (keyword, indexed_values)) in results.iter().enumerate() {
            let obj = Object::new();
            Reflect::set(
                &obj,
                &JsValue::from_str("keyword"),
                &Uint8Array::from(keyword.to_vec().as_slice()),
            )
            .map_err(|e| WasmError(format!("failed setting `keyword` into Js object: {e:?}")))?;
            let sub_array = Array::new_with_length((indexed_values.len()) as u32);
            for (j, value) in indexed_values.iter().enumerate() {
                let js_array = Uint8Array::from(value.to_vec().as_slice());
                sub_array.set(j as u32, js_array.into());
            }
            Reflect::set(&obj, &JsValue::from_str("results"), &sub_array).map_err(|e| {
                WasmError(format!("failed setting `results` into Js object: {e:?}"))
            })?;
            array.set(i as u32, obj.into());
        }
        Ok(SearchResults::from(JsValue::from(array)))
    }
}

#[wasm_bindgen]
extern "C" {
    /// See [`FindexCallbacks::progress()`](crate::core::FindexCallbacks::progress).
    #[wasm_bindgen(
        typescript_type = "(progressResults: Array<{ keyword: Uint8Array, results: \
                           Array<Uint8Array> }>) => Promise<Boolean>"
    )]
    pub type Interrupt;
}

#[wasm_bindgen]
extern "C" {
    /// Findex progress callback result type.
    ///
    /// See [crate::core::FindexCallbacks::progress].
    #[wasm_bindgen(typescript_type = "Array<{ keyword: Uint8Array, results: Array<Uint8Array> }>")]
    pub type InterruptInput;
}

impl TryFrom<HashMap<Keyword, HashSet<IndexedValue<Keyword, Location>>>> for InterruptInput {
    type Error = WasmError;

    fn try_from(
        results: HashMap<Keyword, HashSet<IndexedValue<Keyword, Location>>>,
    ) -> Result<Self, WasmError> {
        let array = Array::new_with_length(results.len() as u32);
        for (i, (keyword, indexed_values)) in results.into_iter().enumerate() {
            let obj = Object::new();
            Reflect::set(
                &obj,
                &JsValue::from_str("keyword"),
                &Uint8Array::from(keyword.to_vec().as_slice()),
            )
            .map_err(|e| WasmError(format!("failed setting `keyword` into Js object: {e:?}")))?;
            let sub_array = Array::new_with_length((indexed_values.len()) as u32);
            for (j, value) in indexed_values.into_iter().enumerate() {
                let js_array = Uint8Array::from(<Vec<u8>>::from(&value).as_slice());
                sub_array.set(j as u32, js_array.into());
            }
            Reflect::set(&obj, &JsValue::from_str("results"), &sub_array).map_err(|e| {
                WasmError(format!("failed setting `results` into Js object: {e:?}"))
            })?;
            array.set(i as u32, obj.into());
        }
        Ok(Self::from(JsValue::from(array)))
    }
}

#[wasm_bindgen]
extern "C" {
    /// JS Array of `Uint8Array` representing data indexed by Findex.
    #[wasm_bindgen(typescript_type = "Array<Uint8Array>")]
    #[derive(Debug)]
    pub type IndexedData;
}

impl From<&HashSet<Location>> for IndexedData {
    fn from(indexed_data: &HashSet<Location>) -> Self {
        let array = Array::new();
        for data in indexed_data {
            let js_data = unsafe { Uint8Array::new(&Uint8Array::view(data)) };
            array.push(&js_data);
        }
        Self::from(JsValue::from(array))
    }
}

impl TryFrom<IndexedData> for HashSet<Location> {
    type Error = WasmError;

    fn try_from(value: IndexedData) -> Result<Self, Self::Error> {
        let array: &Array = value.dyn_ref().ok_or_else(|| {
            WasmError(format!(
                "`IndexedData` should be an array, {} received.",
                value
                    .js_typeof()
                    .dyn_ref::<JsString>()
                    .map_or_else(|| "unknown type".to_owned(), |s| format!("{s}")),
            ))
        })?;

        array
            .values()
            .into_iter()
            .enumerate()
            .map(|(i, try_data)| {
                try_data
                    .map_err(|e| WasmError(format!("failed getting data at index {i}: {e:?}")))
                    .map(|data| Location::from(Uint8Array::from(data).to_vec()))
            })
            .collect()
    }
}

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(
        typescript_type = "(indexedData: Array<Uint8Array>) => Promise<Array<Uint8Array>>"
    )]
    pub type Filter;
}

#[wasm_bindgen]
extern "C" {
    /// JS Array of `UInt8Array` used to pass keywords to Findex
    /// [`search`](crate::core::FindexSearch::search).
    #[wasm_bindgen(typescript_type = "Array<Uint8Array>")]
    #[derive(Debug)]
    pub type ArrayOfKeywords;
}

impl From<&Keywords> for ArrayOfKeywords {
    fn from(keywords: &Keywords) -> Self {
        let array = Array::new();
        for kw in keywords.iter() {
            let js_kw = unsafe { Uint8Array::new(&Uint8Array::view(kw)) };
            array.push(&js_kw);
        }
        Self::from(JsValue::from(array))
    }
}

#[wasm_bindgen]
extern "C" {
    /// JS Array of indexed values and their associated keywords to upsert.
    #[wasm_bindgen(typescript_type = "Array<{indexedValue: Uint8Array, keywords: Uint8Array[]}>")]
    #[derive(Debug)]
    pub type IndexedValuesAndKeywords;
}

impl TryFrom<&IndexedValuesAndKeywords>
    for HashMap<IndexedValue<Keyword, Location>, HashSet<Keyword>>
{
    type Error = WasmError;

    fn try_from(value: &IndexedValuesAndKeywords) -> Result<Self, Self::Error> {
        let array: &Array = value.dyn_ref().ok_or_else(|| {
            WasmError(format!(
                "`IndexedValuesAndKeywords` should be an array, {} received.",
                value
                    .js_typeof()
                    .dyn_ref::<JsString>()
                    .map_or_else(|| "unknown type".to_owned(), |s| format!("{s}")),
            ))
        })?;

        let mut iv_and_words = HashMap::new();
        for (i, try_obj) in array.values().into_iter().enumerate() {
            let obj = try_obj.map_err(|e| {
                WasmError(format!("could not get array element at index {i}: {e:?}"))
            })?;
            let indexed_value =
                get_bytes_from_object_property(&obj, "indexedValue").map_err(|e| {
                    WasmError(format!(
                        "could not get `indexedValue` at offset {i} from '{value:?}': {e:?}"
                    ))
                })?;
            let indexed_value = IndexedValue::try_from(indexed_value.as_slice()).map_err(|e| {
                WasmError(format!("cannot parse `IndexedValue` at index {i}: {e:?}"))
            })?;
            let keywords = Array::from(
                &Reflect::get(&obj, &JsValue::from_str("keywords")).map_err(|e| {
                    WasmError(format!("could not get `keywords` at offset {i}: {e:?}"))
                })?,
            );
            let keywords = keywords
                .values()
                .into_iter()
                .enumerate()
                .map(|(j, try_kw)| {
                    try_kw
                        .map_err(|e| {
                            WasmError(format!("could not get keyword at index ({i}, {j}): {e:?}"))
                        })
                        .map(|kw| {
                            let bytes = Uint8Array::from(kw).to_vec();
                            Keyword::from(bytes)
                        })
                })
                .collect::<Result<_, _>>()?;
            iv_and_words.insert(indexed_value, keywords);
        }
        Ok(iv_and_words)
    }
}
