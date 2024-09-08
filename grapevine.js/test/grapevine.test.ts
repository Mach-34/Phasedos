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

let mockAuthSignature = (eddsa: Eddsa, sk: Buffer): { nullifier: Buffer, authSignature: Signature } => {
  let nullifier = eddsa.F.e(crypto.randomBytes(32)) as Buffer;
  let authSignature = eddsa.signPoseidon(sk, nullifier);
  return { nullifier, authSignature };
};

describe("Grapevine", () => {
  let wasm: GrapevineWasm;
  let keys: Buffer[] = [];
  let poseidon: Poseidon;
  let eddsa: Eddsa;
  let F: any;
  let artifacts: WasmArtifacts;

  before(async () => {
    wasm = await GrapevineUtils.initGrapevineWasm();
    for (let i = 0; i < 10; i++) {
      keys.push(crypto.randomBytes(32));
    }
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
    // verify the identity proof to get the outputs
    let identityProofOutput = await wasm.verify_grapevine_proof(identityProof, artifacts.params, 0);
    // create inputs for degree proof
    let { nullifier, authSignature } = mockAuthSignature(eddsa, keys[0]);
    // get input maps
    input_map = GrapevineUtils.makeDegreeInput(
      poseidon,
      eddsa,
      keys[1],
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
    // let [nullifier, signature] = mockAuthSignature(eddsa, keys[0]);
    // console.log("Nullifier: ", nullifier);
    // console.log("Signature: ", signature);
  });
});
