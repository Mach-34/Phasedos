import { expect } from "chai";
import * as GrapevineUtils from "../src/utils";
import { GrapevineWasm } from "../src/consts";
import { GrapevineWasmArtifacts } from "../src/types";
import * as crypto from "crypto";
import {
  Eddsa,
  Point,
  Poseidon,
  Signature,
  buildEddsa,
  buildPoseidon,
} from "circomlibjs";

let mockAuthSignature = (
  eddsa: Eddsa,
  poseidon: Poseidon,
  sender: Buffer,
  recipient: Point
): { nullifier: Buffer; authSignature: Signature } => {
  // choose random nullifier
  let nullifier = poseidon.F.e(crypto.randomBytes(32));
  // get the pubkey of the prover
  let recipientAddress = poseidon(recipient);
  // hash the auth secret scoped
  let msg = poseidon([
    poseidon.F.toObject(nullifier),
    poseidon.F.toObject(recipientAddress),
  ]);
  // sign the auth secret
  let authSignature = eddsa.signPoseidon(sender, msg);
  return { nullifier: Buffer.from(nullifier), authSignature };
};

describe("Grapevine", () => {
  let wasm: GrapevineWasm;
  let keys: Buffer[] = [];
  let poseidon: Poseidon;
  let eddsa: Eddsa;
  let F: any;
  let artifacts: GrapevineWasmArtifacts;

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
  it("Single Degree Test", async () => {
    // create inputs for identity proof
    let input_map = GrapevineUtils.makeIdentityInput(poseidon, eddsa, keys[0]);
    let chaff_map = GrapevineUtils.makeRandomInput(poseidon, eddsa);
    // run identity proof
    let identityProof = await wasm.identity_proof(
      artifacts,
      JSON.stringify(input_map),
      JSON.stringify(chaff_map),
      true
    );
    // verify the identity proof to get the outputs
    let identityProofOutput = await wasm.verify_grapevine_proof(
      identityProof,
      artifacts.params,
      0
    );
    // create an auth secret (nullifier + sig over nullifier) from identity prover to degree 1
    let { nullifier, authSignature } = mockAuthSignature(
      eddsa,
      poseidon,
      keys[0],
      eddsa.prv2pub(keys[1])
    );
    // create inputs for degree proof
    input_map = GrapevineUtils.makeDegreeInput(
      poseidon,
      eddsa,
      keys[1], // prover (degree 1) private key
      eddsa.prv2pub(keys[0]), // relation (previous prover) public key 
      authSignature, // auth signature over H|nullifier, proverAddress|
      nullifier, // nullifier given to current prover
      GrapevineUtils.parseScopeAddress(F, identityProofOutput[2]) // identity scope for proof chain
    );
    chaff_map = GrapevineUtils.makeRandomInput(poseidon, eddsa);
    // run degree proof
    let degreeProof = await wasm.degree_proof(
      artifacts,
      JSON.stringify(input_map),
      JSON.stringify(chaff_map),
      identityProof,
      identityProofOutput,
      true
    );
    // verify degree proof
    let degreeProofOutput = await wasm.verify_grapevine_proof(
        degreeProof,
        artifacts.params,
        1
    );
  });
});
