import { buildEddsa, buildPoseidon, } from "circomlibjs";
import { initGrapevineWasm, getAvailableProofs, proveAvailable, defaultArtifacts, makeIdentityInput, makeRandomInput, deriveAuthSecret, makeDegreeInput, getProvenDegrees } from "./utils.ts";
import { addRelationship, getPendingRelationships, nullifyRelationship } from "./user.ts";


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

const proveServer = async () => {
    const eddsa = await buildEddsa();
    const wasm = await initGrapevineWasm()

    const privkey1 = "b5a4c309f5fb71c45ef24ee90e91411d5203db8f948fc18dc9ccd073c30f6b26";
    const privkey2 = "1603adb60ef063a939b1659f2fc344c3f3920168b7c0f75d3015f8959c5372ce";

    const user1 = {
        privkey: privkey1,
        pubkey: eddsa.prv2pub(Buffer.from(privkey1, 'hex')),
        username: 'testuser'
    };

    const user2 = {
        privkey: privkey2,
        pubkey: eddsa.prv2pub(Buffer.from(privkey2, 'hex')),
        username: 'usertest'
    }


    const relationshipResponse1 = await addRelationship(wasm, user2.username, user1);
    console.log('Res: 1', relationshipResponse1);

    const pending = await getPendingRelationships(user2);

    const relationshipResponse2 = await addRelationship(wasm, user1.username, user2);
    console.log('Res: 2', relationshipResponse2);

    const availableProofs = await getAvailableProofs(user1);
    console.log("Available proofs for user1", availableProofs);
    await proveAvailable(wasm, availableProofs, user1);

    const proven = await getProvenDegrees(user1);
    console.log('Proven: ', proven);


    const nullifyRes1 = await nullifyRelationship(wasm, user2.username, user1);
    // console.log('First nullification: ', nullifyRes1);

    const nullifyRes2 = await nullifyRelationship(wasm, user1.username, user2);
    // console.log('Second nullification: ', nullifyRes2);
}


(async () => {
    // await proveLocal();
    await proveServer();
})();