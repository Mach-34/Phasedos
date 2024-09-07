import { buildEddsa } from "circomlibjs";
import { Scalar } from "ffjavascript";
// import * as crypto from "crypto";


// // let key = "0001020304050607080900010203040506070809000102030405060708090001";
// let key = "cb9d33e3fbb84808e164cc75fced9380edb92e5c0c72cc9951def29c469fd3d8"
// /**
//  * Converts value to expected form
//  * @param value 
//  */
// let convertValue = (value: Uint8Array, F: any): Buffer => {
//     const hexBE = F.toObject(value).toString(16);
//     let buf = Buffer.from(hexBE, 'hex');
//     return buf.reverse()
// }

// let main = async () => {
//     // let q = crypto.randomBytes(32);
//     // console.log("Random bytes: ", q.toString('hex'));
//     let eddsa = await buildEddsa();
//     let poseidon = await buildPoseidon();
//     let F = eddsa.F;
//     let pubkey = eddsa.prv2pub(Buffer.from(key, 'hex'));
//     let x = convertValue(pubkey[0], F);
//     let y = convertValue(pubkey[1], F);
//     console.log("Public key X: ", x.toString('hex'));
//     console.log("Public key Y: ", y.toString('hex'));
//     // console.log("y: ", F.toObject(pubkey[1]));

//     // console.log("xxx", pubkey[0]);
//     // let message = [F.e(pubkey[0]), F.e(pubkey[1])];
//     // let address = poseidon(message);
//     // console.log(`Computed address: 0x${Buffer.from(address).toString('hex')}`);
// }

// main();

function padBufferTo32Bytes(buffer: Buffer) {
    if (buffer.length > 32) {
        throw new Error("Buffer is already larger than 32 bytes");
    }

    // Create a new 32-byte buffer filled with zeros
    const paddedBuffer = Buffer.alloc(32);

    // Copy the original buffer to the end of the new buffer
    buffer.copy(paddedBuffer, 32 - buffer.length);

    return paddedBuffer;
}

(async () => {
    const eddsa = await buildEddsa();
    const username = 'testuser';
    const privkey = "0xd6071fcce61f192d88959e26e15ed22495cefacc574e664dbcee2728ad7e410f";
    const buff = padBufferTo32Bytes(Buffer.from(username, 'utf8'));
    const msg = eddsa.babyJub.F.e(Scalar.fromRprLE(buff, 0));
    const SERVER_URL = "http://localhost:8000";
    const url = `${SERVER_URL}/user/nonce`;

    const signature = eddsa.signPoseidon(privkey, msg);

    const payload = {
        signature: Array.from(eddsa.packSignature(signature)),
        username: "testuser"
    };

    const res = await fetch(url, {
        body: JSON.stringify(payload),
        method: "POST",
        headers: { "content-type": 'application/json' }
    });
    const data = await res.json();
    console.log('Data: ', data);
})();