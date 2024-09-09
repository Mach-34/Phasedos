import { PARAMS_URI, NUM_PARAMS_CHUNKS, WASM_URI, R1CS_URI } from "./consts";
import init, * as GrapevineWasmModule from "../wasm/grapevine_wasm";
import { WasmArtifacts } from "./types"; 
import { fileURLToPath } from "url";
import { dirname } from "path";
import { BabyJub, Eddsa, Point, Poseidon, Signature } from "circomlibjs";
import { InputMap } from "./types";
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
  let ds = new DecompressionStream("gzip");
  let reader = blob.stream().pipeThrough(ds).getReader();
  let done = false;
  let params = "";
  while (!done) {
    let decompressed = await reader.read();
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

export const defaultArtifacts =
  async (): Promise<WasmArtifacts> => {
    const params = await getParams();
    const paramsString = await decompressParamsBlob(params);
    return new WasmArtifacts(
      paramsString,
      R1CS_URI,
      WASM_URI
    );
  };

export const randomSignature = (eddsa: Eddsa): Signature => {
  let key = crypto.randomBytes(32);
  let randomMessage = eddsa.F.e(crypto.randomBytes(32));
  let signature = eddsa.signPoseidon(key, randomMessage);
  return signature;
};

export const makeIdentityInput = (
  poseidon: Poseidon,
  eddsa: Eddsa,
  key: Buffer
): InputMap => {
  // make real inputs
  let proverPubkey = eddsa.prv2pub(key);
  let address = poseidon(proverPubkey);
  let scopeSignature = eddsa.signPoseidon(key, address);

  // make dummy inputs
  let relationKey = crypto.randomBytes(32);
  let relationPubkey = eddsa.prv2pub(relationKey);
  let authSignature = randomSignature(eddsa);
  let relationNullifier = poseidon.F.e(crypto.randomBytes(32));

  return {
    prover_pubkey: proverPubkey.map((x) => poseidon.F.toObject(x).toString()),
    relation_pubkey: relationPubkey.map((x) =>
      poseidon.F.toObject(x).toString()
    ),
    relation_nullifier: poseidon.F.toObject(relationNullifier).toString(),
    auth_signature: [
      poseidon.F.toObject(authSignature.R8[0]).toString(),
      poseidon.F.toObject(authSignature.R8[1]).toString(),
      authSignature.S.toString(),
    ],
    scope_signature: [
      poseidon.F.toObject(scopeSignature.R8[0]).toString(),
      poseidon.F.toObject(scopeSignature.R8[1]).toString(),
      scopeSignature.S.toString(),
    ],
  };
};


export const makeDegreeInput = (
  poseidon: Poseidon,
  eddsa: Eddsa,
  proverKey: Buffer,
  relationPubkey: Point,
  authSignature: Signature,
  relationNullifier: Buffer,
  scope: Point
) => {
  // fix scope
  // let strippedHex = scope.startsWith('0x') ? scope.slice(2) : scope;
  // let scopeBytes = new Uint8Array(strippedHex.match(/.{1,2}/g)!.map(byte => parseInt(byte, 16)))
  // let msgBuf = eddsa.babyJub.F.e(Scalar.fromRprLE(scopeBytes, 0))
  let decimal = BigInt(`${scope}`);
  let bytes = new Uint8Array(Buffer.from(decimal.toString(16), 'hex'));

  console.log("Computed", BigInt("0x" + Buffer.from(bytes).toString('hex')));

  let proverPubkey = eddsa.prv2pub(proverKey);
  let scopeSignature = eddsa.signPoseidon(proverKey, poseidon(relationPubkey));

  return {
    prover_pubkey: proverPubkey.map((x) => poseidon.F.toObject(x).toString()),
    relation_pubkey: relationPubkey.map((x) => poseidon.F.toObject(x).toString()),
    relation_nullifier: poseidon.F.toObject(relationNullifier).toString(),
    auth_signature: [
      poseidon.F.toObject(authSignature.R8[0]).toString(),
      poseidon.F.toObject(authSignature.R8[1]).toString(),
      authSignature.S.toString(),
    ],
    scope_signature: [
      poseidon.F.toObject(scopeSignature.R8[0]).toString(),
      poseidon.F.toObject(scopeSignature.R8[1]).toString(),
      scopeSignature.S.toString(),
    ],
  };
}

export const makeRandomInput = (
  poseidon: Poseidon,
  eddsa: Eddsa
): InputMap => {
  let proverKey = crypto.randomBytes(32);
  let proverPubkey = eddsa.prv2pub(proverKey);
  let relationKey = crypto.randomBytes(32);
  let relationPubkey = eddsa.prv2pub(relationKey);
  let scopeSignature = randomSignature(eddsa);
  let authSignature = randomSignature(eddsa);
  let relationNullifier = poseidon.F.e(crypto.randomBytes(32));
  return {
    prover_pubkey: proverPubkey.map((x) => poseidon.F.toObject(x).toString()),
    relation_pubkey: relationPubkey.map((x) =>
      poseidon.F.toObject(x).toString()
    ),
    relation_nullifier: poseidon.F.toObject(relationNullifier).toString(),
    auth_signature: [
      poseidon.F.toObject(authSignature.R8[0]).toString(),
      poseidon.F.toObject(authSignature.R8[1]).toString(),
      authSignature.S.toString(),
    ],
    scope_signature: [
      poseidon.F.toObject(scopeSignature.R8[0]).toString(),
      poseidon.F.toObject(scopeSignature.R8[1]).toString(),
      scopeSignature.S.toString(),
    ],
  };
};

export const deriveNullifier = async (poseidon: Poseidon, eddsa: Eddsa, sk: Buffer, pk: Point) => {

}

export const deriveAesKey = async (bjj: BabyJub, sk: Buffer, pk: Point): Promise<[Buffer, Buffer]> => {
  let secret = bjj.mulPointEscalar(pk, sk);
  let seed = Buffer.concat([Buffer.from(secret[0]), Buffer.from(secret[1])]);
  let hasher = crypto.createHash("sha256");
  let hash = hasher.update(seed).digest();
  let key = hash.subarray(0, 16);
  let iv = hash.subarray(16, 32);
  return [key, iv];
};