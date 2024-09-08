import { expect } from "chai";
import * as GrapevineUtils from "../src/utils";
import { GrapevineWasm } from "../src/consts";
import { WasmArtifacts } from "../src/types";
import * as crypto from "crypto";
import { Eddsa, Poseidon, buildEddsa, buildPoseidon } from "circomlibjs";

let convertValue = (value: Uint8Array, F: any): Buffer => {
  const hexBE = F.toObject(value).toString(16).padStart(64, "0");
  let buf = Buffer.from(hexBE, "hex");
  return buf.reverse();
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
    //artifacts = await GrapevineUtils.defaultArtifacts();
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
    console.log("Res return length: ", res.length);
    console.log("Params length: ", artifacts.params.length);
    // verify the identity proof
    let verified = await wasm.verify_grapevine_proof(res, artifacts.params, 0);
    console.log("Verified: ", verified);
  });
  xit("Params test", async () => {
    let params = artifacts.params;
    console.log("Params: ", params.length);
    params = artifacts.params;
    console.log("Params: ", params.length);
  });
  it("AES Keygen test", async () => {
    let sk = keys[0].toString("hex");
    let pk = eddsa.prv2pub(keys[1]);
    let pk_x = convertValue(pk[0], F).toString("hex");
    let pk_y = convertValue(pk[1], F).toString("hex");
    console.log("Private key: ", sk);
    console.log("Public key x: ", pk_x);
    console.log("Public key y: ", pk_y);
        let input_map = GrapevineUtils.makeIdentityInput(poseidon, eddsa, keys[0]);

    let aes_key = await wasm.derive_aes_key(sk, pk_x, pk_y);
    console.log("AES Key: ", aes_key);
  })
});
