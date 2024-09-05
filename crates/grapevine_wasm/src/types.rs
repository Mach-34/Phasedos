// use grapevine_circuits::inputs::GrapevineInputs;
// use serde::{Deserialize, Serialize};
// use js_sys::Array;
// use crate::{utils::bigint_to_fr_ce, StringArray};
// use grapevine_common::compat::convert_ff_to_ff_ce;
// use babyjubjub_rs::{Point, Signature};

// // pub struct PointWasm {
// //     pub x: String,
// //     pub y: String,
// // }

// // pub struct SignatureWasm {
// //     pub r_b8: PointWasm,
// //     pub s: String,
// // }

// // #[derive(Debug, Clone, Serialize, Deserialize)]
// // pub struct GrapevineWasmInputs {
// //     pub nullifier: Option<String>,
// //     pub prover_pubkey: PointWasm,
// //     pub relation_pubkey: Option<PointWasm>,
// //     pub scope_signature: SignatureWasm,
// //     pub auth_signature: Option<SignatureWasm>,
// // }

// // #[derive(Debug, Clone, Serialize, Deserialize)]
// // pub struct GrapevineWasmOutputs {
// //     pub nullifier: Array,
// //     pub relation_pubkey: PointWasm,
// //     pub scope_signature: SignatureWasm,
// //     pub auth_signature: SignatureWasm,
// // }

// // impl TryInto<GrapevineInputs> for GrapevineWasmInputs {
// //     type Error = String;

// //     fn try_into(self) -> Result<GrapevineInputs, Self::Error> {
// //         let prover_pubkey = Point {
// //             x: bigint_to_fr_ce(&self.prover_pubkey.x)?,
// //             y: bigint_to_fr_ce(&self.prover_pubkey.y)?,
// //         };
// //         let relation_pubkey = match self.relation_pubkey {
// //             Some(relation_pubkey) => Some(Point {
// //                 x: bigint_to_fr_ce(&relation_pubkey.x)?,
// //                 y: bigint_to_fr_ce(&relation_pubkey.y)?,
// //             }),
// //             None => None,
// //         };
// //         let scope_signature = Signature {
// //             r_b8: Point {
// //                 x: bigint_to_fr_ce(&self.scope_signature.r_b8.x)?,
// //                 y: bigint_to_fr_ce(&self.scope_signature.r_b8.y)?,
// //             },
// //             s: bigint_to_fr_ce(&self.scope_signature.s)?,
// //         };
// //         let auth_signature = match self.auth_signature {
// //             Some(auth_signature) => Some(Signature {
// //                 r_b8: Point {
// //                     x: bigint_to_fr_ce(&auth_signature.r_b8.x)?,
// //                     y: bigint_to_fr_ce(&auth_signature.r_b8.y)?,
// //                 },
// //                 s: bigint_to_fr_ce(&auth_signature.s)?,
// //             }),
// //             None => None,
// //         };

// //         Ok(GrapevineInputs {
// //             nullifier: match self.nullifier {
// //                 Some(nullifier) => Some(bigint_to_fr(&nullifier)?),
// //                 None => None,
// //             },
// //             prover_pubkey,
// //             relation_pubkey,
// //             scope_signature,
// //             auth_signature,
// //         })
// //     }
// // }

// // #[wasm_bindgen]
// // pub struct WasmArtifacts {
// //     params: String,
// //     r1cs_url: String,
// //     wasm_url: String,
// // }

// // #[wasm_bindgen]
// // impl WasmArtifacts {
// //     pub fn new(params: String, r1cs_url: String, wasm_url: String) -> Self {
// //         Self {
// //             params,
// //             r1cs_url,
// //             wasm_url,
// //         }
// //     }

// //     pub fn params(&self) -> String {
// //         self.params.clone()
// //     }

// //     pub fn r1cs_url(&self) -> String {
// //         self.r1cs_url.clone()
// //     }

// //     pub fn wasm_url(&self) -> String {
// //         self.wasm_url.clone()
// //     }
// // }