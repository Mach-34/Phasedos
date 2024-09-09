import { expect } from "chai";
import * as GrapevineUtils from "../src/utils";
import { GrapevineWasm } from "../src/consts";
import { WasmArtifacts } from "../src/types";
import * as crypto from "crypto";
import {
  Eddsa,
  Poseidon,
  Signature,
  buildEddsa,
  buildPoseidon,
} from "circomlibjs";

let convertValue = (value: Uint8Array, F: any): Buffer => {
  const hexBE = F.toObject(value).toString(16).padStart(64, "0");
  let buf = Buffer.from(hexBE, "hex");
  return buf.reverse();
};

let mockAuthSignature = (
  eddsa: Eddsa,
  poseidon: Poseidon,
  sk: Buffer
): { nullifier: Buffer; authSignature: Signature } => {
  let pubkey = eddsa.prv2pub(sk);
  let address = Buffer.from(poseidon(pubkey));
  let authSignature = eddsa.signPoseidon(sk, address);
  return { nullifier: address, authSignature };
};

const privateKeys = [
    'e5a2fefac0fa70ee4c139702ca0e9adb888175a005d92fd7b297dfc78be69ad6',
    '59fcd3722074b1f96f5e0e9f7d398d2a3ddea13e6a1fd04c207336d0b76d585d',
    '946a6ba1caf036d4ff6fb7b3f89d68dc7430b37e214bfff45f600e9d554bdc3b',
    'd7130a03de91dff1843e78b43c8e627c85c1fad12c06249551daabc2f29e7741',
    'f31357628cfa9935158cddd80b1378a194738299e6cf6b4602d2490060c26b23',
    '82edb793b8ab68c3feab124e4254a5368f6e1a01c8f3a914e01f08135ae5f587',
    '1176ed9ea1ffb1656c49293f6c90c4c10af384da0acb0646709b8b2dc01161ce',
    '43d06e29b62dacb9efbf852ddf2657e660e4d15e28eab13557adfe4511327355',
    'c7377885ab8084285dd352c22d102333882e1aaf9f3acd863f56f5505e9906fa',
    'c8dbd5316fad816f096d5e37074ac7d975862897390048f289b6f62d8c34aa2f'
  ]

describe("Grapevine", () => {
  let wasm: GrapevineWasm;
  let keys: Buffer[] = [];
  let poseidon: Poseidon;
  let eddsa: Eddsa;
  let F: any;
  let artifacts: WasmArtifacts;

  before(async () => {
    wasm = await GrapevineUtils.initGrapevineWasm();
    // for (let i = 0; i < 10; i++) {
    //   keys.push(crypto.randomBytes(32));
    // }
    keys = privateKeys.map((key) => Buffer.from(key, "hex"));
    poseidon = await buildPoseidon();
    eddsa = await buildEddsa();
    F = poseidon.F;
    console.log("Downloading proving artifacts...");
    artifacts = await GrapevineUtils.defaultArtifacts();
  });
  xit("Test the bn", async () => {
    let x = 12348023482034820384023840238402834028340283402834023n;
    let y = await wasm.bigint_test(x);
  });
  xit("Do an identity Proof", async () => {
    // get circuit inputs
    let input_map = GrapevineUtils.makeIdentityInput(poseidon, eddsa, keys[0]);
    let chaff_map = GrapevineUtils.makeRandomInput(poseidon, eddsa);
    console.log("Input map: ", input_map);
    // run identity proof
    let res = await wasm.identity_proof(
      artifacts,
      JSON.stringify(input_map),
      JSON.stringify(chaff_map),
      true
    );
    // verify the identity proof
    let verified = await wasm.verify_grapevine_proof(res, artifacts.params, 0);
  });
  it("Degree Proof", async () => {
    // generate identity proof
    let input_map = GrapevineUtils.makeIdentityInput(poseidon, eddsa, keys[0]);
    console.log("Input map: ", input_map);
    let chaff_map = GrapevineUtils.makeRandomInput(poseidon, eddsa);
    let identityProof = await wasm.identity_proof(
      artifacts,
      JSON.stringify(input_map),
      JSON.stringify(chaff_map),
      true
    );

    let alicePubkey = eddsa.prv2pub(keys[0]);
    let readable = {
        x: F.toObject(alicePubkey[0]).toString(),
        y: F.toObject(alicePubkey[1]).toString()
    };
    console.log("Address: ", F.toObject(poseidon(alicePubkey).toString()).toString(16));
    console.log("Alice pubkey: ", readable);

    // verify the identity proof to get the outputs
    let identityProofOutput = await wasm.verify_grapevine_proof(
      identityProof,
      artifacts.params,
      0
    );
    console.log("Identity proof output: ", identityProofOutput);
    
   

    // create inputs for degree proof
    let { nullifier, authSignature } = mockAuthSignature(eddsa, poseidon, keys[0]);
    console.log("Nullifier: ", nullifier.toString('hex'));

    alicePubkey = eddsa.prv2pub(keys[0]);
    readable = {
        x: F.toObject(alicePubkey[0]).toString(),
        y: F.toObject(alicePubkey[1]).toString()
    };
    console.log("Alice pubkey: ", readable);
    // get input maps
    input_map = GrapevineUtils.makeDegreeInput(
      poseidon,
      eddsa,
      keys[1],
      eddsa.prv2pub(keys[0]),
      authSignature,
      nullifier
    );
    chaff_map = GrapevineUtils.makeRandomInput(poseidon, eddsa);
    console.log("Input map: ", input_map);
    // run degree proof
    let degreeProof = await wasm.degree_proof(
      artifacts,
      JSON.stringify(input_map),
      JSON.stringify(chaff_map),
      identityProof,
      identityProofOutput,
      true
    );
  });
  xit("Params test", async () => {
    let params = artifacts.params;
    console.log("Params: ", params.length);
    params = artifacts.params;
    console.log("Params: ", params.length);
  });
  xit("Test mock signature", async () => {
    let { nullifier, authSignature } = mockAuthSignature(eddsa, poseidon, keys[0]);
    console.log("Nullifier: ", nullifier);
    console.log("Signature: ", authSignature);

  });
});
