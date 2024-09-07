import { expect } from "chai";
import * as GrapevineUtils from "../src/utils";
import { GrapevineWasm } from "../src/consts";
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

  before(async () => {
    wasm = await GrapevineUtils.initGrapevineWasm();
    for (let i = 0; i < 10; i++) {
      keys.push(crypto.randomBytes(32));
    }
    poseidon = await buildPoseidon();
    eddsa = await buildEddsa();
    F = poseidon.F;
  });
  xit("Test the bn", async () => {
    let x = 12348023482034820384023840238402834028340283402834023n;
    let y = await wasm.bigint_test(x);
  });
  it("Do an identity Proof", async () => {
    // get the params
    let params = await GrapevineUtils.defaultArtifacts();
    // get circuit inputs
    let pubkey = eddsa.prv2pub(keys[0]);
    let address = poseidon(pubkey);
    let signature = eddsa.signPoseidon(keys[0], address);
    let pubkey_x = convertValue(pubkey[0], F).toString("hex")
    let pubkey_y = convertValue(pubkey[1], F).toString("hex")
    let sig_r8_a = convertValue(signature.R8[0], F).toString("hex")
    let sig_8_b = convertValue(signature.R8[1], F).toString("hex")
    let sig_s = signature.S.toString(16);
    let res = await wasm.identity_proof(params, pubkey_x, pubkey_y, sig_r8_a, sig_8_b, sig_s);
    console.log("res: ", res);
  });
});
