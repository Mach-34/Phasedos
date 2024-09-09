/* tslint:disable */
/* eslint-disable */
/**
*
* * Creates a new IVC Proof representing identity (degree 0)
* *
* * @param params_string - JSON string of the public parameters
* * @param r1cs_url - URL of the r1cs file
* * @param wasm_url - URL of the wasm file
* * @param prover_key - JSON string of the prover key
* * @returns JSON string of the proof
* 
* @param {GrapevineWasmArtifacts} artifact_locations
* @param {string} input_map
* @param {string} chaff_map
* @param {boolean} verbose
* @returns {Promise<string>}
*/
export function identity_proof(artifact_locations: GrapevineWasmArtifacts, input_map: string, chaff_map: string, verbose: boolean): Promise<string>;
/**
* @param {GrapevineWasmArtifacts} artifact_locations
* @param {string} input_map
* @param {string} chaff_map
* @param {string} proof_string
* @param {Array<any>} previous_output
* @param {boolean} verbose
* @returns {Promise<string>}
*/
export function degree_proof(artifact_locations: GrapevineWasmArtifacts, input_map: string, chaff_map: string, proof_string: string, previous_output: Array<any>, verbose: boolean): Promise<string>;
/**
*
* * Verify the correct execution of an IVC proof of the grapevine circuit
* *
* * @param proof - the proof to verify
* * @param public_params - the public params to use to verify the proof
* * @param iterations - the degree of separation proven (iterations should equal 2*degree + 2)
* * @return - the output of the proof if verified
* 
* @param {string} params_string
* @param {string} proof
* @param {number} degree
* @param {boolean} verbose
* @returns {Promise<Array<any>>}
*/
export function verify_grapevine_proof(params_string: string, proof: string, degree: number, verbose: boolean): Promise<Array<any>>;
/**
* @param {string} path
* @returns {Promise<Uint8Array>}
*/
export function read_file(path: string): Promise<Uint8Array>;
/**
* @param {string} input_json_string
* @param {string} wasm_file
* @returns {Promise<Uint8Array>}
*/
export function generate_witness_browser(input_json_string: string, wasm_file: string): Promise<Uint8Array>;
/**
* @param {number} num_threads
* @returns {Promise<any>}
*/
export function initThreadPool(num_threads: number): Promise<any>;
/**
* @param {number} receiver
*/
export function wbg_rayon_start_worker(receiver: number): void;
/**
*/
export class GrapevineWasmArtifacts {
  free(): void;
/**
* @param {string} params
* @param {string} r1cs_url
* @param {string} wasm_url
*/
  constructor(params: string, r1cs_url: string, wasm_url: string);
/**
*/
  readonly params: string;
/**
*/
  readonly r1cs_url: string;
/**
*/
  readonly wasm_url: string;
}
/**
*/
export class wbg_rayon_PoolBuilder {
  free(): void;
/**
* @returns {number}
*/
  numThreads(): number;
/**
* @returns {number}
*/
  receiver(): number;
/**
*/
  build(): void;
}

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
  readonly __wbg_grapevinewasmartifacts_free: (a: number, b: number) => void;
  readonly grapevinewasmartifacts_new: (a: number, b: number, c: number, d: number, e: number, f: number) => number;
  readonly grapevinewasmartifacts_params: (a: number, b: number) => void;
  readonly grapevinewasmartifacts_r1cs_url: (a: number, b: number) => void;
  readonly grapevinewasmartifacts_wasm_url: (a: number, b: number) => void;
  readonly identity_proof: (a: number, b: number, c: number, d: number, e: number, f: number) => number;
  readonly degree_proof: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number) => number;
  readonly verify_grapevine_proof: (a: number, b: number, c: number, d: number, e: number, f: number) => number;
  readonly __wbg_wbg_rayon_poolbuilder_free: (a: number, b: number) => void;
  readonly wbg_rayon_poolbuilder_numThreads: (a: number) => number;
  readonly wbg_rayon_poolbuilder_receiver: (a: number) => number;
  readonly wbg_rayon_poolbuilder_build: (a: number) => void;
  readonly initThreadPool: (a: number) => number;
  readonly wbg_rayon_start_worker: (a: number) => void;
  readonly read_file: (a: number, b: number) => number;
  readonly generate_witness_browser: (a: number, b: number, c: number, d: number) => number;
  readonly memory: WebAssembly.Memory;
  readonly __wbindgen_malloc: (a: number, b: number) => number;
  readonly __wbindgen_realloc: (a: number, b: number, c: number, d: number) => number;
  readonly __wbindgen_export_3: WebAssembly.Table;
  readonly _dyn_core__ops__function__FnMut__A____Output___R_as_wasm_bindgen__closure__WasmClosure___describe__invoke__hb49cb808e4b64cd1: (a: number, b: number, c: number) => void;
  readonly __wbindgen_add_to_stack_pointer: (a: number) => number;
  readonly __wbindgen_free: (a: number, b: number, c: number) => void;
  readonly __wbindgen_exn_store: (a: number) => void;
  readonly wasm_bindgen__convert__closures__invoke2_mut__h8d4df63bb4d69126: (a: number, b: number, c: number, d: number) => void;
  readonly __wbindgen_thread_destroy: (a?: number, b?: number, c?: number) => void;
  readonly __wbindgen_start: (a: number) => void;
}

export type SyncInitInput = BufferSource | WebAssembly.Module;
/**
* Instantiates the given `module`, which can either be bytes or
* a precompiled `WebAssembly.Module`.
*
* @param {{ module: SyncInitInput, memory?: WebAssembly.Memory, thread_stack_size?: number }} module - Passing `SyncInitInput` directly is deprecated.
* @param {WebAssembly.Memory} memory - Deprecated.
*
* @returns {InitOutput}
*/
export function initSync(module: { module: SyncInitInput, memory?: WebAssembly.Memory, thread_stack_size?: number } | SyncInitInput, memory?: WebAssembly.Memory): InitOutput;

/**
* If `module_or_path` is {RequestInfo} or {URL}, makes a request and
* for everything else, calls `WebAssembly.instantiate` directly.
*
* @param {{ module_or_path: InitInput | Promise<InitInput>, memory?: WebAssembly.Memory, thread_stack_size?: number }} module_or_path - Passing `InitInput` directly is deprecated.
* @param {WebAssembly.Memory} memory - Deprecated.
*
* @returns {Promise<InitOutput>}
*/
export default function __wbg_init (module_or_path?: { module_or_path: InitInput | Promise<InitInput>, memory?: WebAssembly.Memory, thread_stack_size?: number } | InitInput | Promise<InitInput>, memory?: WebAssembly.Memory): Promise<InitOutput>;
