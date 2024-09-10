import { PARAMS_URI, NUM_PARAMS_CHUNKS, WASM_URI, R1CS_URI, SERVER_URL, GrapevineWasm } from "./consts.ts";
import init, * as GrapevineWasmModule from "../wasm/grapevine_wasm.js";
import {
  AuthSecret,
  GrapevineOutputs,
  GrapevineOutputSlot,
  GrapevineWasmArtifacts,
} from "./types.ts";
import { fileURLToPath } from "url";
import { dirname } from "path";
import { BabyJub, buildEddsa, Eddsa, Point, Poseidon, Signature } from "circomlibjs";
import { InputMap, User } from "./types";
import * as crypto from "crypto";
import { Scalar } from "ffjavascript";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

/**
 * Retrieve the nova params as a gzip-compressed blob
 * @todo: allow redirecting the url for retrieving params?
 *
 * @param parallel - whether to fetch all chunks in parallel or sequential (default true = parallelize)
 * @returns - the gzipped blob of the params
 */
export const getParams = async (parallel = true): Promise<Blob> => {
  let requests = []; // only used if parallel
  let data: Map<Number, Blob> = new Map();
  for (let i = 0; i < NUM_PARAMS_CHUNKS; i++) {
    const uri = PARAMS_URI(i);
    const request = fetchWithRetry(uri, {
      headers: { contentType: "application/x-binary" },
    });
    // if parallel, push request to resolve later
    if (parallel) requests.push(request);
    // otherwise resolve now
    else data.set(i, await request.then(async (res) => await res.blob()));
  }
  if (parallel) {
    // resolve all requests in parallel
    const responses = await Promise.all(requests);
    for (let i = 0; i < NUM_PARAMS_CHUNKS; i++)
      data.set(i, await responses[i].blob());
  }
  // build into one blob
  let chunks = [];
  for (let i = 0; i < 10; i++) {
    chunks.push(data.get(i)!);
  }
  return new Blob(chunks);
};

/**
 * Decompresses a gzipped blob into the stringified json used by the wasm module for proving/ verifying
 *
 * @param blob - the gzipped blob of params
 * @returns - the stringified json of the params
 */
export const decompressParamsBlob = async (blob: Blob): Promise<string> => {
  const ds = new DecompressionStream("gzip");
  const reader = blob.stream().pipeThrough(ds).getReader();
  let done = false;
  let params = "";
  while (!done) {
    const decompressed = await reader.read();
    done = decompressed.done;
    params += new TextDecoder().decode(decompressed.value);
  }
  return params;
};

/**
 * Makes a fetch request and retries it a specified number of times until success
 *
 * @param url - the url to make http request to
 * @param options - request options
 * @param retries - number of times to retry
 * @param backoff - delay period before retrying
 */
export const fetchWithRetry = async (
  url: string,
  options?: RequestInit,
  retries: number = 3,
  backoff: number = 200
): Promise<Response> => {
  try {
    const response = await fetch(url, options);
    if (!response.ok && retries > 0) {
      throw new Error("Fetch failed");
    }
    return response;
  } catch (e) {
    console.log(`Failed fetch of "${url}" with ${retries} retries left`);
    if (retries > 0) {
      await new Promise((resolve) => setTimeout(resolve, backoff));
      return fetchWithRetry(url, options, retries - 1, backoff * 2);
    } else {
      throw e;
    }
  }
};

/**
 * Initialize a wasm instance of the grapevine proving API
 *
 * @param threads - the number of threads to use in the web worker pool (if available)
 * @returns - the wasm module
 */
export const initGrapevineWasm = async (threads = 1): Promise<any> => {
  let wasm;

  if (typeof window !== "undefined") {
    // Browser-specific loading
    wasm = await import("../wasm/grapevine_wasm");
    await wasm.default();
    if (threads > 1) {
      let concurrency = navigator.hardwareConcurrency;
      if (threads > concurrency)
        console.warn(
          `Requested ${threads} threads but only ${concurrency} available`
        );
      else concurrency = threads;
      await wasm.initThreadPool(concurrency);
    }
  } else {
    const fs = await import("fs");
    const path = await import("path");
    const wasmPath = path.resolve(__dirname, "../wasm/grapevine_wasm_bg.wasm");
    const wasmBytes = fs.readFileSync(wasmPath);
    await init(wasmBytes);
  }
  return GrapevineWasmModule;
};

/**
 * Get all default artifacts used by the Grapevine proving API
 * @returns - downloaded params and URL for r1cs and circuit wasm
 */
export const defaultArtifacts = async (): Promise<GrapevineWasmArtifacts> => {
  const params = await getParams();
  const paramsString = await decompressParamsBlob(params);
  return new GrapevineWasmArtifacts(paramsString, R1CS_URI, WASM_URI);
};

const randomSignature = (eddsa: Eddsa): Signature => {
  const key = crypto.randomBytes(32);
  const randomMessage = eddsa.F.e(crypto.randomBytes(32));
  const signature = eddsa.signPoseidon(key, randomMessage);
  return signature;
};

/**
 * Generate the input map for an identity proof starting a degree chain in Grapevine
 *
 * @param poseidon - the circomlibjs Poseidon hash function
 * @param eddsa - the circomlibjs Eddsa signature scheme
 * @param key - the private key of the prover running the circuit
 * @returns - an input map formatted for the circom circuit's witness calculator
 */
export const makeIdentityInput = (
  poseidon: Poseidon,
  eddsa: Eddsa,
  prover: Buffer
): InputMap => {
  // derive prover pubkey
  const proverPubkey = eddsa.prv2pub(prover);
  // sign own address since identity step = setting scope
  const address = poseidon(proverPubkey);
  const scopeSignature = eddsa.signPoseidon(prover, address);
  // random relation
  const relationKey = crypto.randomBytes(32);
  const relationPubkey = eddsa.prv2pub(relationKey);
  // random relation nullifier
  const relationNullifier = poseidon.F.e(crypto.randomBytes(32));
  // random auth signature
  const authSignature = randomSignature(eddsa);
  // build input map
  return makeInputMap(
    poseidon.F,
    proverPubkey,
    relationPubkey,
    relationNullifier,
    authSignature,
    scopeSignature
  );
};

/**
 * Generate the input map for a degree proof demonstrating relation to a previous proof in a Grapevine chain
 *
 * @param eddsa - the circomlibjs Eddsa signature scheme
 * @param prover - the private key of the prover running the circuit
 * @param relationPubkey - the pubkey of the previous prover that the current proof is built from
 * @param relationNullifier - the nullifier issued by the relation to the prover
 * @param authSignature - the signature by the relation over the hash H|nullifier, proverAddress|
 * @param scope - the stringified scope address outputted from a GrapevineProof
 * @returns - an input map formatted for the circom circuit's witness calculator
 */
export const makeDegreeInput = (
  eddsa: Eddsa,
  prover: Buffer,
  relationPubkey: Point,
  authSecret: AuthSecret,
  scope: String
) => {
  // get the prover's pubkey from their private key
  const proverPubkey = eddsa.prv2pub(prover);
  // parse and sign the scope (identity proof address)
  const parsedScope = parseGrapevineOutput(eddsa.F, scope);
  const scopeSignature = eddsa.signPoseidon(prover, parsedScope);
  // build the input map
  return makeInputMap(
    eddsa.F,
    proverPubkey,
    relationPubkey,
    authSecret.nullifier,
    authSecret.signature,
    scopeSignature
  );
};

/**
 * Generate random satisfying witness for the chaff step of the Grapevine circuit
 *
 * @param poseidon - the circomlibjs Poseidon hash function
 * @param eddsa - the circomlibjs Eddsa signature scheme
 * @returns - input map for a Grapevine chaff step
 */
export const makeRandomInput = (poseidon: Poseidon, eddsa: Eddsa): InputMap => {
  // random prover
  const proverKey = crypto.randomBytes(32);
  const proverPubkey = eddsa.prv2pub(proverKey);
  // random relation
  const relationKey = crypto.randomBytes(32);
  const relationPubkey = eddsa.prv2pub(relationKey);
  // random nullifier
  const relationNullifier = poseidon.F.e(crypto.randomBytes(32));
  // random auth signature
  const scopeSignature = randomSignature(eddsa);
  // random scope signature
  const authSignature = randomSignature(eddsa);
  // build input map
  return makeInputMap(
    poseidon.F,
    proverPubkey,
    relationPubkey,
    relationNullifier,
    authSignature,
    scopeSignature
  );
};

/**
 * Utility for creating an input map for all step types in the Grapevine Circuit
 *
 * @param F - the Field api for normalizing values
 * @param proverPubkey - the pubkey of the prover running the circuit
 * @param relationPubkey - the pubkey of the previous prover that the current proof is built from
 * @param relationNullifier - the nullifier issued by the relation to the prover
 * @param authSignature - the signature by the relation over the hash H|nullifier, proverAddress|
 * @param scopeSignature - the signature by the prover over the identity proof creator's address
 * @returns - an input map formatted for the circom circuit's witness calculator
 */
const makeInputMap = (
  F: any,
  proverPubkey: Point,
  relationPubkey: Point,
  relationNullifier: Uint8Array,
  authSignature: Signature,
  scopeSignature: Signature
): InputMap => {
  return {
    prover_pubkey: proverPubkey.map((x) => F.toObject(x).toString()),
    relation_pubkey: relationPubkey.map((x) => F.toObject(x).toString()),
    relation_nullifier: F.toObject(relationNullifier).toString(),
    auth_signature: [
      F.toObject(authSignature.R8[0]).toString(),
      F.toObject(authSignature.R8[1]).toString(),
      authSignature.S.toString(),
    ],
    scope_signature: [
      F.toObject(scopeSignature.R8[0]).toString(),
      F.toObject(scopeSignature.R8[1]).toString(),
      scopeSignature.S.toString(),
    ],
  };
};

/**
 * Generate a random nullifier secret to store and auth secret for a relation to issue to a prover
 *
 * @param poseidon - the circomlibjs Poseidon hash function
 * @param eddsa - the circomlibjs Eddsa signature scheme
 * @param sender - the private key of the user creating auth secret for recipient to use to prove relation
 * @param recipient - the public key of the recipient of the auth secret
 * @returns nullifierSecret - the trapdoor used by the relation to nullify the relationship
 * @returns authSecret - the auth secret used by the prover to prove relation to previous proof creator
 */
export const deriveAuthSecret = (
  poseidon: Poseidon,
  eddsa: Eddsa,
  sender: Buffer,
  recipient: Point
): { nullifierSecret: Uint8Array; authSecret: AuthSecret } => {
  // choose random nullifier secret
  const nullifierSecret = poseidon.F.e(crypto.randomBytes(32));
  // hash with own address to get the nullifier
  const senderAddress = poseidon(eddsa.prv2pub(sender));
  const nullifier = poseidon([nullifierSecret, senderAddress]);
  // get the pubkey of the prover
  const recipientAddress = poseidon(recipient);
  // hash the nullifier with the recipient address to get the auth message
  const authMessage = poseidon([nullifier, recipientAddress]);
  // sign the nullifier
  const signature = eddsa.signPoseidon(sender, authMessage);
  return { nullifierSecret, authSecret: { nullifier, signature } };
};

/**
 * Parses an Fr element from the GrapevineWasm output into LE Uint8Array form usable by circomlibjs
 *
 * @param F - the circomlibjs Field api for normalizing values
 * @param fr - the stringified field element outputted by the GrapevineWasm in BE
 * @returns - the Uint8Array representation of the Fr element in LE
 */
export const parseGrapevineOutput = (F: any, fr: String): Uint8Array => {
  let strippedHex = fr.startsWith("0x") ? fr.slice(2) : fr;
  let byteArray = strippedHex.match(/.{1,2}/g);
  let reversedByteArray = byteArray!.reverse();
  let reversedHexString = reversedByteArray.join("");
  let paddedHexString = reversedHexString.padStart(64, "0");
  return F.fromObject("0x" + paddedHexString) as Uint8Array;
};

/**
 * Parse the entire grapevine output array for client use
 *
 * @param F - the circomlibjs Field api for normalizing values
 * @param output - the array of field elements outputted by the GrapevineWasm
 * @returns - the parsed GrapevineOutputs
 */
export const parseGrapevineOutputArray = (
  F: any,
  output: String[]
): GrapevineOutputs => {
  // raw parsing of the output array
  const raw = output.map((x) => parseGrapevineOutput(F, x));
  // parse each field
  const obfuscate = F.toObject(raw[GrapevineOutputSlot.Obfuscate]) === 1n;
  const degree = Number(F.toObject(raw[GrapevineOutputSlot.Degree]));
  const scope = raw[GrapevineOutputSlot.Scope];
  const relation = raw[GrapevineOutputSlot.Relation];
  let nullifiers = [];
  for (let i = GrapevineOutputSlot.Nullifier; i < output.length; i++) {
    nullifiers.push(raw[i]);
  }
  return { obfuscate, degree, scope, relation, nullifiers };
};

export const registerUser = async (
  eddsa: Eddsa,
  poseidon: Poseidon,
  artifacts: GrapevineWasmArtifacts,
  wasm: GrapevineWasm,
  key: Buffer,
  username: string,
  verbose = false
): Promise<string> => {
  // construct identity proof
  const inputMap = makeIdentityInput(eddsa.poseidon, eddsa, key);
  const chaffMap = makeRandomInput(poseidon, eddsa);
  // run identity proof
  const proof = await wasm.identity_proof(
    artifacts,
    JSON.stringify(inputMap),
    JSON.stringify(chaffMap),
    verbose
  );
  // build https inputs
  const pubkey = eddsa.prv2pub(key);
  const packedPubkey = Buffer.from(eddsa.babyJub.packPoint(pubkey)).toString(
    "hex"
  );
  const bincoded = await wasm.bincode_create_user_request(
    username,
    packedPubkey,
    proof
  );
  // make https request
  const url = `${SERVER_URL}/proof/identity`;
  const res = await fetch(url, {
    body: bincoded,
    method: "POST",
    // @ts-ignore
    headers: {
      "content-type": "application/octet-stream",
    },
  });
  const data = await res.text();
  return data;
};


export const generateAuthHeaders = async (user: User) => {
  const eddsa = await buildEddsa();
  const nonce = await getNonce(user.privkey, user.username);
  console.log("nonce", nonce);
  const nonceBytes = nonceToBytes(nonce);

  const usernameBytes = usernametoFr(user.username);

  const hasher = crypto.createHash("sha3-256");
  const digest = hasher.update(usernameBytes).update(nonceBytes).digest();
  const digestBytes = new Uint8Array(digest);
  digestBytes[31] = 0;

  const msg = eddsa.babyJub.F.e(Scalar.fromRprLE(Buffer.from(digestBytes), 0))

  // sign digest
  const signature = eddsa.signPoseidon(Buffer.from(user.privkey, 'hex'), msg);
  const signatureHex = Buffer.from(eddsa.packSignature(signature)).toString('hex');

  return { "X-Authorization": signatureHex, "X-Username": user.username }
}

const getNonce = async (privatekey: string, username: string) => {
  const eddsa = await buildEddsa();
  const privkey = Buffer.from(privatekey, 'hex');
  const msg = eddsa.babyJub.F.e(usernametoFr(username));
  // const buff = Buffer.from(username, 'utf8');
  // const msg = eddsa.babyJub.F.e(Scalar.fromRprLE(buff, 0));

  const signature = eddsa.signPoseidon(privkey, msg);

  const payload = {
    signature: Array.from(eddsa.packSignature(signature)),
    username
  };

  const url = `${SERVER_URL}/user/nonce`;
  const res = await fetch(url, {
    body: JSON.stringify(payload),
    method: "POST",
    headers: { "content-type": 'application/json' }
  });
  return await res.json()
}

export const nonceToBytes = (nonce: number) => {
  const arr = new Uint8Array(8); // Create an 8-byte array
  for (let i = 7; i >= 0; i--) {
    arr[i] = nonce & 0xff; // Extract the lowest 8 bits of the number
    nonce = nonce >> 8; // Shift right by 8 bits
  }
  return arr.reverse();
}

const usernametoFr = (username: string) => {
  if (username.length >= 32) {
    throw Error("Max character length exceeded.");
  }
  const padded = new Uint8Array(32)
  const usernameBytes = new Uint8Array(Buffer.from(username, 'utf-8'));
  for (let i = 0; i < usernameBytes.length; i++) {
    padded[30 - i] = usernameBytes[i];
  }
  return padded;
}

export const getAvailableProofs = async (user: User): Promise<string[]> => {
  const url = `${SERVER_URL}/proof/available`;
  const res = await fetch(url, {
    method: "GET",
    headers: {
      ...(await generateAuthHeaders(user))
    }
  });
  return await res.json();
}