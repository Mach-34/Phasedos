import { buildEddsa, buildPoseidon } from "circomlibjs";
import * as crypto from "crypto";

// let key = "0001020304050607080900010203040506070809000102030405060708090001";
let key = "cb9d33e3fbb84808e164cc75fced9380edb92e5c0c72cc9951def29c469fd3d8"
/**
 * Converts value to expected form
 * @param value 
 */
let convertValue = (value: Uint8Array, F: any): Buffer => {
    const hexBE = F.toObject(value).toString(16);
    let buf = Buffer.from(hexBE, 'hex');
    return buf.reverse()
}

let main = async () => {
    // let q = crypto.randomBytes(32);
    // console.log("Random bytes: ", q.toString('hex'));
    let eddsa = await buildEddsa();
    let poseidon = await buildPoseidon();
    let F = eddsa.F;
    let pubkey = eddsa.prv2pub(Buffer.from(key, 'hex'));
    let x = convertValue(pubkey[0], F);
    let y = convertValue(pubkey[1], F);
    console.log("Public key X: ", x.toString('hex'));
    console.log("Public key Y: ", y.toString('hex'));
    // console.log("y: ", F.toObject(pubkey[1]));

    // console.log("xxx", pubkey[0]);
    // let message = [F.e(pubkey[0]), F.e(pubkey[1])];
    // let address = poseidon(message);
    // console.log(`Computed address: 0x${Buffer.from(address).toString('hex')}`);
}

main();