import { buildEddsa, buildPoseidon, } from "circomlibjs";
import { initGrapevineWasm, getAvailableProofs, proveAvailable, defaultArtifacts, makeIdentityInput, makeRandomInput, deriveAuthSecret, makeDegreeInput } from "./utils.ts";
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


const proveLocal = async () => {
    const eddsa = await buildEddsa();
    const poseidon = await buildPoseidon();
    const keys = [
        Buffer.from("dda4e349a469ee48c59c72fa72ea21854bc7f57bb66890988fda83527dd30057", 'hex'),
        Buffer.from("11061bc4c9b5a4885d7ce398b34c963a437e13ea9e4bbb7dcda638c13cafecf5", "hex")
    ];
    const wasm = await initGrapevineWasm();
    const artifacts = await defaultArtifacts();

    let inputMap = makeIdentityInput(poseidon, eddsa, keys[0]);
    let chaffMap = makeRandomInput(poseidon, eddsa);

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
    const { authSecret } = deriveAuthSecret(
        poseidon,
        eddsa,
        keys[0],
        eddsa.prv2pub(keys[1])
    );
    // create inputs for degree proof
    inputMap = makeDegreeInput(
        eddsa,
        keys[1], // prover (degree 1) private key
        eddsa.prv2pub(keys[0]), // relation (previous prover) public key
        authSecret, // auth secret given by previous prover to current prover
        identityProofOutput[2] // scope address for proof chain outputted by previous proof
    );

    console.log('Input map: ', inputMap)

    chaffMap = makeRandomInput(poseidon, eddsa);
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
}


(async () => {
    await proveLocal();
    // 

    // const eddsa = await buildEddsa();
    // const wasm = await initGrapevineWasm()

    // const privkey1 = "dda4e349a469ee48c59c72fa72ea21854bc7f57bb66890988fda83527dd30057";
    // const privkey2 = "11061bc4c9b5a4885d7ce398b34c963a437e13ea9e4bbb7dcda638c13cafecf5";

    // const user1 = {
    //     privkey: privkey1,
    //     pubkey: eddsa.prv2pub(Buffer.from(privkey1, 'hex')),
    //     username: 'testuser'
    // };

    // const user2 = {
    //     privkey: privkey2,
    //     pubkey: eddsa.prv2pub(Buffer.from(privkey2, 'hex')),
    //     username: 'usertest'
    // }


    // const relationshipResponse1 = await addRelationship(wasm, user2.username, user1);
    // console.log('First relationship creation: ', relationshipResponse1);

    // const pending = await getPendingRelationships(user2);
    // console.log('Pending: ', pending)

    // const relationshipResponse2 = await addRelationship(wasm, user1.username, user2);
    // console.log('Second relationship creation: ', relationshipResponse2);

    // const availableProofs = await getAvailableProofs(user1);
    // // console.log("Available proofs for user1", availableProofs);

    // await proveAvailable(wasm, availableProofs, user1);

    // const nullifyRes1 = await nullifyRelationship(wasm, user2.username, user1);
    // // console.log('First nullification: ', nullifyRes1);

    // const nullifyRes2 = await nullifyRelationship(wasm, user1.username, user2);
    // // console.log('Second nullification: ', nullifyRes2);
})();