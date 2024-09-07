export const ARTIFACT_BASE_URI = "https://bjj-ecdsa-nova.us-southeast-1.linodeobjects.com/grapevine/v1";
export const PARAMS_URI = (chunk: number) => `${ARTIFACT_BASE_URI}/params_${chunk}.gz`;
export const NUM_PARAMS_CHUNKS = 10;
export const WASM_URI = `${ARTIFACT_BASE_URI}/grapevine.wasm`;
export const R1CS_URI = `${ARTIFACT_BASE_URI}/grapevine.r1cs`;
export type GrapevineWasm = typeof import("../wasm/grapevine_wasm")