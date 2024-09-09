import { Signature } from "circomlibjs"

export { GrapevineWasmArtifacts } from "../wasm/grapevine_wasm.js"

// map of inputs formatted for use in circom witcalc
export type InputMap = {
    relation_pubkey: String[],
    prover_pubkey: String[],
    relation_nullifier: String,
    auth_signature: String[],
    scope_signature: String[]
}

// auth secret issued by a relation that a prover uses to show direction relationship with
export type AuthSecret = {
    nullifier: Uint8Array, // H|nullifierSecret, recipientAddress|
    signature: Signature // Sig|nullifier|
}

// indices in GrapevineOutput array
export enum GrapevineOutputSlot {
    Obfuscate = 0, // flag set whether or not to run chaff step
    Degree = 1, // the degree of separation proven in the verified proof (0 = identity)
    Scope = 2, // the scope address of the proof indicating who everyone is proving separation from
    Relation = 3, // the relation address denoting the prover showing they are N degrees separated from the scope
    Nullifier = 4, // the stat of the nullifiers - to access a specific nullifier, add the index to this
}

// Grapevine outputs formatted for manual use
export type GrapevineOutputs = {
    obfuscate: boolean,
    degree: number,
    scope: Uint8Array,
    relation: Uint8Array,
    nullifiers: Uint8Array[]
}