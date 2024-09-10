import { expect } from "chai";
import * as GrapevineUtils from "../src/utils";
import { GrapevineWasm } from "../src/consts";
import {
  AuthSecret,
  GrapevineOutputSlot,
  GrapevineWasmArtifacts,
} from "../src/types";
import * as crypto from "crypto";
import { Eddsa, Poseidon, buildEddsa, buildPoseidon } from "circomlibjs";
import { addRelationship } from "../src/user";

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

  it("Degree 1 Test", async () => {
    // create inputs for identity proof
    let inputMap = GrapevineUtils.makeIdentityInput(poseidon, eddsa, keys[0]);
    let chaffMap = GrapevineUtils.makeRandomInput(poseidon, eddsa);
    // run identity proof
    const identityProof = await wasm.identity_proof(
      artifacts,
      JSON.stringify(inputMap),
      JSON.stringify(chaffMap),
      true
    );
    // verify the identity proof to get the outputs
    const identityProofOutput = await wasm.verify_grapevine_proof(
      artifacts.params,
      identityProof,
      0,
      true
    );
    // create an auth secret (nullifier + sig over nullifier) from identity prover to degree 1
    const { authSecret } = GrapevineUtils.deriveAuthSecret(
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
    const degreeProof = await wasm.degree_proof(
      artifacts,
      JSON.stringify(inputMap),
      JSON.stringify(chaffMap),
      identityProof,
      identityProofOutput,
      true
    );
    // verify degree proof
    const degreeProofOutput = await wasm.verify_grapevine_proof(
      artifacts.params,
      degreeProof,
      1,
      true
    );
  });

  xit("Basic Degree 8 test", async () => {
    // derive auth secrets for users 0->8
    let authSecrets: AuthSecret[] = [];
    for (let i = 0; i < 8; i++) {
      let recipient = eddsa.prv2pub(keys[i + 1]);
      let { authSecret } = GrapevineUtils.deriveAuthSecret(
        poseidon,
        eddsa,
        keys[i],
        recipient
      );
      authSecrets.push(authSecret);
    }
    /// IDENTITY PROOF ///
    // create inputs for identity proof
    console.log("Creating Grapevine Identity Proof...");
    let inputMap = GrapevineUtils.makeIdentityInput(poseidon, eddsa, keys[0]);
    let chaffMap = GrapevineUtils.makeRandomInput(poseidon, eddsa);
    // run identity proof
    let proof = await wasm.identity_proof(
      artifacts,
      JSON.stringify(inputMap),
      JSON.stringify(chaffMap),
      false
    );
    console.log("Verifying Grapevine Identity Proof...");
    // verify the identity proof to get the outputs
    let proofOutput = await wasm.verify_grapevine_proof(
      artifacts.params,
      proof,
      0,
      false
    );
    // validate proof outputs match expectations
    const expectedScope = Buffer.from(
      poseidon(eddsa.prv2pub(keys[0]))
    ).toString("hex");
    const zero = Buffer.from(poseidon.F.e(0n)).toString("hex");
    let expectedRelation = expectedScope;
    let expectedNullifiers = [];
    let empiricalOutputs = GrapevineUtils.parseGrapevineOutputArray(
      poseidon.F,
      proofOutput
    );
    expect(empiricalOutputs.obfuscate).to.equal(false);
    expect(empiricalOutputs.degree).to.equal(0);
    expect(Buffer.from(empiricalOutputs.scope).toString("hex")).to.equal(
      expectedScope
    );
    expect(Buffer.from(empiricalOutputs.relation).toString("hex")).to.equal(
      expectedRelation
    );
    for (let i = 0; i < 8; i++) {
      expect(
        Buffer.from(empiricalOutputs.nullifiers[i]).toString("hex")
      ).to.equal(zero);
    }
    /// DEGREE PROOFS ///
    for (let i = 1; i < 9; i++) {
      console.log(`Creating Grapevine Proof of Degree ${i}...`);
      // context
      const prover = keys[i];
      const relationPubkey = eddsa.prv2pub(keys[i - 1]); // this will be sent to the prover
      const authSecret = authSecrets[i - 1];
      const scope = proofOutput[GrapevineOutputSlot.Scope];
      // create inputs for degree proof
      inputMap = GrapevineUtils.makeDegreeInput(
        eddsa,
        prover,
        relationPubkey,
        authSecret,
        scope
      );
      chaffMap = GrapevineUtils.makeRandomInput(poseidon, eddsa);
      // run degree proof
      proof = await wasm.degree_proof(
        artifacts,
        JSON.stringify(inputMap),
        JSON.stringify(chaffMap),
        proof,
        proofOutput,
        false
      );
      // verify degree proof
      console.log(`Verifying Grapevine Proof of Degree ${i}...`);
      proofOutput = await wasm.verify_grapevine_proof(
        artifacts.params,
        proof,
        i,
        false
      );
      // validate proof outputs match expectations
      expectedNullifiers.push(
        Buffer.from(authSecret.nullifier).toString("hex")
      );
      expectedRelation = Buffer.from(poseidon(eddsa.prv2pub(prover))).toString(
        "hex"
      );
      const empiricalOutputs = GrapevineUtils.parseGrapevineOutputArray(
        poseidon.F,
        proofOutput
      );
      expect(empiricalOutputs.obfuscate).to.equal(false);
      expect(empiricalOutputs.degree).to.equal(i);
      expect(Buffer.from(empiricalOutputs.scope).toString("hex")).to.equal(
        expectedScope
      );
      expect(Buffer.from(empiricalOutputs.relation).toString("hex")).to.equal(
        expectedRelation
      );
      for (let j = 0; j < 8; j++) {
        const empiricalNullifier = Buffer.from(
          empiricalOutputs.nullifiers[j]
        ).toString("hex");
        if (j < i) {
          expect(empiricalNullifier).to.equal(expectedNullifiers[j]);
        } else expect(empiricalNullifier).to.equal(zero);
      }
    }
  });

  xdescribe("Server tests", async () => {
    
    it("Register two users", async () => {
        const user0 = {
            privkey: keys[0].toString('hex'),
            pubkey: eddsa.prv2pub(keys[0]),
            username: `user_${crypto.randomBytes(4).toString("hex")}`
        };
        const user1 = {
            privkey: keys[1].toString('hex'),
            pubkey: eddsa.prv2pub(keys[1]),
            username: `user_${crypto.randomBytes(4).toString("hex")}`
        };
        await GrapevineUtils.registerUser(
            eddsa,
            poseidon,
            artifacts,
            wasm,
            keys[0],
            user0.username
        );
        await GrapevineUtils.registerUser(
            eddsa,
            poseidon,
            artifacts,
            wasm,
            keys[1],
            user1.username
        );
    });
    it("Establish relationship between users", async () => {
        const user0 = {
            privkey: keys[0].toString('hex'),
            pubkey: eddsa.prv2pub(keys[0]),
            username: `user_${crypto.randomBytes(4).toString("hex")}`
        };
        const user1 = {
            privkey: keys[1].toString('hex'),
            pubkey: eddsa.prv2pub(keys[1]),
            username: `user_${crypto.randomBytes(4).toString("hex")}`
        };
        await addRelationship(wasm, user1.username, user0);
        await addRelationship(wasm, user0.username, user1);
    });
    it("Prove next degree of separation", async () => {
        const user0 = {
            privkey: keys[0].toString('hex'),
            pubkey: eddsa.prv2pub(keys[0]),
            username: `user_${crypto.randomBytes(4).toString("hex")}`
        };
        const user1 = {
            privkey: keys[1].toString('hex'),
            pubkey: eddsa.prv2pub(keys[1]),
            username: `user_${crypto.randomBytes(4).toString("hex")}`
        };
        // get available proofs for user0
        const availableProofs = await GrapevineUtils.getAvailableProofs(user0);
        console.log("Available proofs for user0", availableProofs);
    })
  });

  describe("Bincode Tests", async () => {
    // this is dummy data with the right size. Just replace with the right data
    xit("Create relationship request", async () => {
      const to = "Username";
      const ephemeralKey = crypto.randomBytes(32).toString("hex");
      const signatureCiphertext = crypto.randomBytes(80).toString("hex");
      const nullifierCiphertext = crypto.randomBytes(48).toString("hex");
      const nullifierSecretCiphertext = crypto.randomBytes(48).toString("hex");
      const bincoded = await wasm.bincode_new_relationship_request(
        to,
        ephemeralKey,
        signatureCiphertext,
        nullifierCiphertext,
        nullifierSecretCiphertext
      );
      console.log("bincoded", bincoded.length);
    });
    xit("Emit nullifier request", async () => {
      const to = "Username";
      const nullifierSecret = crypto.randomBytes(32).toString("hex");
      const bincoded = await wasm.bincode_emit_nullifier_request(
        nullifierSecret,
        to
      );
      console.log("bincoded", bincoded.length);
    });
    xit("Create user request", async () => {
      // build proof
      let inputMap = GrapevineUtils.makeIdentityInput(poseidon, eddsa, keys[0]);
      let chaffMap = GrapevineUtils.makeRandomInput(poseidon, eddsa);
      // run identity proof
      let proof = await wasm.identity_proof(
        artifacts,
        JSON.stringify(inputMap),
        JSON.stringify(chaffMap),
        false
      );
      // mock other inputs
      let username = "Username";
      let pubkey = crypto.randomBytes(32).toString("hex");
      // bincode
      let bincoded = await wasm.bincode_create_user_request(
        username,
        pubkey,
        proof
      );
      console.log("bincoded", bincoded.length);
    });
    xit("Degree proof request", async () => {
      // build proof
      let inputMap = GrapevineUtils.makeIdentityInput(poseidon, eddsa, keys[0]);
      let chaffMap = GrapevineUtils.makeRandomInput(poseidon, eddsa);
      // run identity proof (it looks basically the same as a degree proof so its fine)
      let proof = await wasm.identity_proof(
        artifacts,
        JSON.stringify(inputMap),
        JSON.stringify(chaffMap),
        false
      );
      // mock other inputs
      let previous = "oufwehfro9h30928r";
      let degree = 4;
      // bincode
      let bincoded = await wasm.bincode_degree_proof_request(
        proof,
        previous,
        degree
      );
      console.log("bincoded", bincoded.length);
    });
  });
});
