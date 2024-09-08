import { buildEddsa } from "circomlibjs";
import { Scalar } from "ffjavascript";
import * as crypto from "crypto";


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

type User = {
    privkey: string;
    username: string;
}


const SERVER_URL = "http://localhost:8000";

const addRelationship = async (recipient: string, sender: User) => {
    const payload = {
        ephemeral_key: [], // TODO
        nullifier_ciphertext: [], // TODO
        nullifier_secret_ciphertext: [], // TODO
        signature_ciphertext: [], // TODO
        to: recipient,
    };

    const url = `${SERVER_URL}/user/relationship/add`
    const res = await fetch(url, {
        body: JSON.stringify(payload),
        method: "POST",
        // @ts-ignore
        headers: {
            "content-type": 'application/json',
            ...(await genAuthHeaders(sender))
        }
    });
    return await res.json()
}

const getNonce = async (privatekey: string, username: string) => {
    const eddsa = await buildEddsa();
    const privkey = Buffer.from(privatekey, 'hex');
    const buff = Buffer.from(username, 'utf8');
    const msg = eddsa.babyJub.F.e(Scalar.fromRprLE(buff, 0));

    const signature = eddsa.signPoseidon(privkey, msg);

    const payload = {
        signature: Array.from(eddsa.packSignature(signature)),
        username
    };

    const url = `${SERVER_URL}/user/nonce`;
    const res = await fetch(url, {
        body: JSON.stringify(payload),
        method: "POST",
        headers: { "content-type": 'application/json' }
    });
    return await res.json()
}

const getNullifierSecret = async (recipient: string, user: User) => {
    const url = `${SERVER_URL}/user/${recipient}/nullifier-secret`;
    const res = await fetch(url, {
        method: "GET",
        // @ts-ignore
        headers: {
            ...(await genAuthHeaders(user))
        }
    });
    return await res.text()
}

const nullifyRelationship = async (recipient: string, sender: User) => {

    const nullifierSecret = await getNullifierSecret(recipient, sender);
    // TODO: Decrypt nullifier secret

    const payload = {
        nullifier_secret: [], // TODO
        recipient
    };

    const url = `${SERVER_URL}/user/relationship/nullify`;
    const res = await fetch(url, {
        body: JSON.stringify(payload),
        method: "POST",
        // @ts-ignore
        headers: {
            "content-type": 'application/json',
            ...(await genAuthHeaders(sender))
        }
    });
    return await res.json()
}

const genAuthHeaders = async (user: User) => {
    const eddsa = await buildEddsa();
    const nonce = await getNonce(user.privkey, user.username);
    const nonceBytes = nonceToBytes(nonce);

    const usernameBytes = usernametoFr(user.username);

    const hasher = crypto.createHash("sha3-256");
    const digest = hasher.update(usernameBytes).update(nonceBytes).digest();
    const digestBytes = new Uint8Array(digest);
    digestBytes[31] = 0;

    const msg = eddsa.babyJub.F.e(Scalar.fromRprLE(Buffer.from(digestBytes), 0))

    // sign digest
    const signature = eddsa.signPoseidon(Buffer.from(user.privkey, 'hex'), msg);
    const signatureHex = Buffer.from(eddsa.packSignature(signature)).toString('hex');

    return { "X-Authorization": signatureHex, "X-Username": user.username }
}

const nonceToBytes = (nonce: number) => {
    const arr = new Uint8Array(8); // Create an 8-byte array
    for (let i = 7; i >= 0; i--) {
        arr[i] = nonce & 0xff; // Extract the lowest 8 bits of the number
        nonce = nonce >> 8; // Shift right by 8 bits
    }
    return arr.reverse();
}

const usernametoFr = (username: string) => {
    if (username.length >= 32) {
        throw Error("Max character length exceeded.");
    }
    const padded = new Uint8Array(32)
    const usernameBytes = new Uint8Array(Buffer.from(username, 'utf-8'));
    for (let i = 0; i < usernameBytes.length; i++) {
        padded[30 - i] = usernameBytes[i];
    }
    return padded;
}

(async () => {


    const user1 = {
        privkey: "d6071fcce61f192d88959e26e15ed22495cefacc574e664dbcee2728ad7e410f",
        username: 'testuser'
    };

    const user2 = {
        privkey: "0bec346cdb813b92956b5f74c3a5f590fe32078ebfdca4580f6c9bbab4020175",
        username: 'testuser2'
    }


    // const res = await addRelationship(user2.username, user1);
})();