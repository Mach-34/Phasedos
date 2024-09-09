import { expect } from "chai";
import * as GrapevineUtils from "../src/utils";
import { GrapevineWasm } from "../src/consts";
import { GrapevineWasmArtifacts } from "../src/types";
import * as crypto from "crypto";
import {
  Eddsa,
  Poseidon,
  buildEddsa,
  buildPoseidon,
} from "circomlibjs";



describe("Grapevine", () => {
  let wasm: GrapevineWasm;
  let keys: Buffer[] = [];
  let poseidon: Poseidon;
  let eddsa: Eddsa;
  let artifacts: GrapevineWasmArtifacts;

  before(async () => {
    wasm = await GrapevineUtils.initGrapevineWasm();
    for (let i = 0; i < 10; i++) {
      keys.push(crypto.randomBytes(32));
    }
    poseidon = await buildPoseidon();
    eddsa = await buildEddsa();
    console.log("Downloading proving artifacts...");
    artifacts = await GrapevineUtils.defaultArtifacts();
  });

  it("Single Degree Test", async () => {
    // create inputs for identity proof
    let inputMap = GrapevineUtils.makeIdentityInput(poseidon, eddsa, keys[0]);
    let chaffMap = GrapevineUtils.makeRandomInput(poseidon, eddsa);
    // run identity proof
    let identityProof = await wasm.identity_proof(
      artifacts,
      JSON.stringify(inputMap),
      JSON.stringify(chaffMap),
      true
    );
    // verify the identity proof to get the outputs
    let identityProofOutput = await wasm.verify_grapevine_proof(
      artifacts.params,
      identityProof,
      0,
      true
    );
    // create an auth secret (nullifier + sig over nullifier) from identity prover to degree 1
    let { authSecret } = GrapevineUtils.deriveAuthSecret(
      poseidon,
      eddsa,
      keys[0],
      eddsa.prv2pub(keys[1])
    );
    // create inputs for degree proof
    inputMap = GrapevineUtils.makeDegreeInput(
      eddsa,
      keys[1], // prover (degree 1) private key
      eddsa.prv2pub(keys[0]), // relation (previous prover) public key
      authSecret, // auth secret given by previous prover to current prover
      identityProofOutput[2] // scope address for proof chain outputted by previous proof
    );
    chaffMap = GrapevineUtils.makeRandomInput(poseidon, eddsa);
    // run degree proof
    let degreeProof = await wasm.degree_proof(
      artifacts,
      JSON.stringify(inputMap),
      JSON.stringify(chaffMap),
      identityProof,
      identityProofOutput,
      true
    );
    // verify degree proof
    let degreeProofOutput = await wasm.verify_grapevine_proof(
      artifacts.params,
      degreeProof,
      1,
      true
    );
  });
});
