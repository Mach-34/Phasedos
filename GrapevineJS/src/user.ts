import { BabyJub, buildEddsa, buildPoseidon, Eddsa, Point, Poseidon } from "circomlibjs";
import * as crypto from "crypto";
import * as ff from "ffjavascript";
import createBlakeHash from 'blake-hash'
import { User } from "./types.ts";
import { SERVER_URL } from "./consts.ts";
import { generateAuthHeaders } from "./utils.ts";

export const addRelationship = async (wasm: any, recipient: string, sender: User) => {

    // get recipient pubkey
    const recipientPubkey = await getUserPubkey(recipient);
    const payload = await generateRelationshipPayload(recipientPubkey, sender);
    const bincoded = await wasm.bincode_new_relationship_request(
        recipient,
        payload.ephemeral_key,
        payload.signature_ciphertext,
        payload.nullifier_ciphertext,
        payload.nullifier_secret_ciphertext
    );
    const url = `${SERVER_URL}/user/relationship/add`
    const res = await fetch(url, {
        body: bincoded, // TODO
        method: "POST",
        // @ts-ignore
        headers: {
            'content-type': 'application/octet-stream',
            ...(await generateAuthHeaders(sender))
        }
    });
    const data = await res.text()
    return data;
}

const decryptAes = (aesKey: Buffer, aesIv: Buffer, ciphertext: Buffer) => {
    const decipher = crypto.createDecipheriv('aes-128-cbc', aesKey, aesIv);
    let decrypted = decipher.update(ciphertext);
    decrypted = Buffer.concat([decrypted, decipher.final()]);
    return decrypted.reverse().toString('hex');
}

const deriveAesKey = async (bjj: BabyJub, sk: any, pk: Point): Promise<[Buffer, Buffer]> => {
    let secret = bjj.mulPointEscalar(pk, sk);
    const secretX = bjj.F.toObject(secret[0]).toString(16).padStart(64, '0');
    const secretY = bjj.F.toObject(secret[1]).toString(16).padStart(64, '0');
    let seed = Buffer.concat([Buffer.from(secretX, 'hex').reverse(), Buffer.from(secretY, 'hex').reverse()]);
    let hasher = crypto.createHash("sha256");
    let hash = hasher.update(seed).digest();
    let key = hash.subarray(0, 16);
    let iv = hash.subarray(16, 32);
    return [key, iv];
};

const encryptAes = (aesKey: Buffer, aesIv: Buffer, plaintext: Buffer): Buffer => {
    const cipher = crypto.createCipheriv('aes-128-cbc', Buffer.from(aesKey), Buffer.from(aesIv));

    // Encrypt the buffer (PKCS7 padding will be applied automatically)
    let encryptedNullifier = cipher.update(plaintext);
    return Buffer.concat([encryptedNullifier, cipher.final()]);
}

const formatPrivKeyForBabyJub = (eddsa: Eddsa, privKey: bigint): bigint => {
    const buffer = Buffer.from(privKey.toString(16), 'hex');
    const sBuff = eddsa.pruneBuffer(
        createBlakeHash('blake512')
            .update(buffer)
            .digest()
            .slice(0, 32),
    )
    const s = ff.utils.leBuff2int(sBuff)
    return ff.Scalar.shr(s, 3)
}

const generateAuthSignature = async (
    eddsa: Eddsa,
    nullifier: Buffer,
    poseidon: Poseidon,
    privkey: Buffer,
    recipientAddress: bigint,
    recipientPubkey: string,
) => {
    const authSecretHash = poseidon([nullifier, recipientAddress]);
    const signature = eddsa.signPoseidon(privkey, authSecretHash);

    // generate ephemeral key
    const ephem_sk = poseidon.F.e(crypto.randomBytes(32));
    const ephem_pk = eddsa.prv2pub(Buffer.from(ephem_sk));

    const recipientPubkeyBytes = new Uint8Array(Buffer.from(recipientPubkey, 'hex'));
    const pubkeyPoint = eddsa.babyJub.unpackPoint(recipientPubkeyBytes);

    const formattedPrivkey = formatPrivKeyForBabyJub(
        eddsa,
        BigInt(`0x${Buffer.from(ephem_sk).toString('hex')}`)
    );

    const [aesKey, aesIv] = await deriveAesKey(eddsa.babyJub, formattedPrivkey, pubkeyPoint);
    const compressedSignature = eddsa.packSignature(signature);

    // encrypt signature
    const signatureCiphertext = encryptAes(aesKey, aesIv, Buffer.from(compressedSignature));

    // encrypt nullifier
    const nullifierCiphertext = encryptAes(aesKey, aesIv, nullifier);

    return { ephem_pk, nullifierCiphertext, signatureCiphertext }
}

const getUserPubkey = async (username: string): Promise<string> => {
    const url = `${SERVER_URL}/user/${username}/pubkey`
    const res = await fetch(url);
    return await res.text()
}

const getNullifierSecret = async (recipient: string, user: User) => {
    const url = `${SERVER_URL}/user/${recipient}/nullifier-secret`;
    const res = await fetch(url, {
        method: "GET",
        // @ts-ignore
        headers: {
            ...(await generateAuthHeaders(user))
        }
    });
    return Buffer.from(await res.arrayBuffer());
}

export const getPendingRelationships = async (user: User) => {
    const url = `${SERVER_URL}/user/relationship/pending`;
    const res = await fetch(url, {
        method: "GET",
        // @ts-ignore
        headers: {
            ...(await generateAuthHeaders(user))
        }
    });
    return await res.json()
}

const generateNullifier = async (poseidon: Poseidon, recipientAddress: bigint) => {
    const nullifierSecret = poseidon.F.toObject(crypto.randomBytes(32)).toString(16).padStart(64, '0');
    const nullifier = poseidon.F.toObject(poseidon([BigInt(`0x${nullifierSecret}`), recipientAddress])).toString(16).padStart(64, '0');
    return { nullifier, nullifierSecret }
}

const generateRelationshipPayload = async (recipient: string, sender: User) => {
    const eddsa = await buildEddsa();
    const poseidon = await buildPoseidon();

    const pubkeyBytes = new Uint8Array(Buffer.from(recipient, 'hex'));
    const pubkey = eddsa.babyJub.unpackPoint(pubkeyBytes);
    const recipientAddress = poseidon.F.toObject(poseidon([pubkey[0], pubkey[1]]));

    const { nullifier, nullifierSecret } = await generateNullifier(poseidon, recipientAddress);

    const { ephem_pk, nullifierCiphertext, signatureCiphertext } = await generateAuthSignature(
        eddsa,
        Buffer.from(nullifier, 'hex'),
        poseidon,
        Buffer.from(sender.privkey, 'hex'),
        recipientAddress,
        recipient
    );

    const formattedPrivkey = formatPrivKeyForBabyJub(
        eddsa,
        BigInt(`0x${sender.privkey}`)
    );

    // encrypt nullifier secret
    const [aesKey, aesIv] = await deriveAesKey(eddsa.babyJub, formattedPrivkey, sender.pubkey);
    const nullifierSecretCiphertext = encryptAes(aesKey, aesIv, Buffer.from(nullifierSecret, 'hex'));

    return {
        ephemeral_key: Buffer.from(eddsa.babyJub.packPoint(ephem_pk)).toString('hex'),
        nullifier_ciphertext: nullifierCiphertext.toString('hex'),
        nullifier_secret_ciphertext: nullifierSecretCiphertext.toString('hex'),
        signature_ciphertext: signatureCiphertext.toString('hex'),
        to: recipient, // TODO: change to username instead of pubkey
    };
}

export const nullifyRelationship = async (wasm: any, recipient: string, sender: User) => {
    const eddsa = await buildEddsa();
    const nullifierSecretCiphertext = await getNullifierSecret(recipient, sender);

    const formattedPrivkey = formatPrivKeyForBabyJub(
        eddsa,
        BigInt(`0x${sender.privkey}`)
    );

    const [aesKey, aesIv] = await deriveAesKey(eddsa.babyJub, formattedPrivkey, sender.pubkey);
    const nullifierSecret = decryptAes(aesKey, aesIv, nullifierSecretCiphertext);

    const bincoded = await wasm.bincode_emit_nullifier_request(nullifierSecret, recipient);

    const url = `${SERVER_URL}/user/relationship/nullify`;
    const res = await fetch(url, {
        body: bincoded,
        method: "POST",
        // @ts-ignore
        headers: {
            'content-type': 'application/octet-stream',
            ...(await generateAuthHeaders(sender))
        }
    });
    return await res.text()
}