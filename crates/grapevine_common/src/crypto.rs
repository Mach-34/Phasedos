use crate::{
    compat::{convert_ff_ce_to_ff, ff_ce_from_le_bytes, ff_ce_to_le_bytes},
    utils::{convert_phrase_to_fr, convert_username_to_fr, random_fr_ce},
    Fr,
};
use babyjubjub_rs::{Point, PrivateKey, Signature};
use num_bigint::{BigInt, RandBigInt, Sign, ToBigInt};
use poseidon_rs::Fr as Fr_ce;
use sha256::digest;
use sha3::{Digest, Sha3_256};

/**
 * Computes an AES-CBC-128 Key from a Baby Jub Jub shared secret
 *
 * @param sk - the private key in the ecdh shared secret
 * @param pk - the public key in the ecdh shared secret (ephemeral in practice)
 * @return - a tuple (AES Key, AES Iv) used to encrypt/ decrypt aes-cbc-128
 */
pub fn gen_aes_key(sk: PrivateKey, pk: Point) -> ([u8; 16], [u8; 16]) {
    // compute ecdh shared secret
    let shared_secret = pk.mul_scalar(&sk.scalar_key());
    // serialize for hash digest
    let secret_buffer = [shared_secret.x, shared_secret.y]
        .iter()
        .map(|el| ff_ce_to_le_bytes(el))
        .flatten()
        .collect::<Vec<u8>>();
    // compute sha256 hash of shared secret
    let hash = digest(&secret_buffer).as_bytes().to_vec();
    // split the hash into the aes key and aes iv
    let aes_key: [u8; 16] = hash[0..16].try_into().unwrap();
    let aes_iv: [u8; 16] = hash[16..32].try_into().unwrap();
    // return
    (aes_key, aes_iv)
}

/**
 * Generates a new private key as a 32 byte array
 *
 * @returns - the new private key
 */
pub fn new_private_key() -> [u8; 32] {
    let mut rng = rand::thread_rng();
    let sk_raw = rng.gen_biguint(1024).to_bigint().unwrap();
    let (_, sk_raw_bytes) = sk_raw.to_bytes_be();
    sk_raw_bytes[..32].try_into().unwrap()
}

/**
 * Computes the sha256 hash H |username, nonce| with last byte zeroed
 *
 * @param username - the username to hash
 * @param nonce - the nonce to hash
 * @return - the sha256 hash of the username and nonce
 */
pub fn nonce_hash(username: &String, nonce: u64) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    // add username to hash buffer
    let username_bytes = convert_username_to_fr(username).unwrap();
    hasher.update(username_bytes);
    // add nonce to hash buffer
    let nonce_bytes = nonce.to_le_bytes();
    hasher.update(nonce_bytes);
    // compute sha256 hash
    let mut hash: [u8; 32] = hasher.finalize().into();
    // 0 the last byte to ensure it always falls within the prime field Fr_ce
    hash[31] = 0;

    hash
}

/**
 * Computes the poseidon hash of a phrase
 * @TODO: FIX THIS HASH IT DOES NOT LINE UP WITH CIRCOM
 *
 * @param phrase - the phrase to hash
 * @return - the poseidon hash of the phrase
 */
pub fn phrase_hash(phrase: &String) -> [u8; 32] {
    let bytes: Vec<Fr_ce> = convert_phrase_to_fr(&phrase)
        .unwrap()
        .iter()
        .map(|fr| ff_ce_from_le_bytes(*fr))
        .collect();

    let hasher = poseidon_rs::Poseidon::new();
    let hash = hasher.hash(bytes).unwrap();
    ff_ce_to_le_bytes(&hash)
}

/**
 * Converts a pubkey to an address using Poseidon(pubkey.x, pubkey.y)
 *
 * @param pubkey - the pubkey to convert into an address
 * @return - the address
 */
pub fn pubkey_to_address(pubkey: &Point) -> Fr_ce {
    let hasher = poseidon_rs::Poseidon::new();
    hasher.hash(vec![pubkey.x, pubkey.y]).unwrap()
}

/**
 * Generates an auth signature and the nullifier bound to a recipient
 *
 * @param from - the issuer of the auth signature
 * @param to - the receipient of the auth signature
 *
 * @return (auth signature, nullifier secret, nullifier)
 *   - 0: the auth signature authorizing "to" to prove relation to & binding the nullifier to "to"
 *   - 1: the nullifier secret used to generate the nullifier - used to prove allowed to emit nullifier
 *   - 2: the nullifier to be shared with the "to" recipient
 */
pub fn sign_auth(from: &PrivateKey, to: &Point) -> (Signature, Fr, Fr) {
    // get the address of to
    let to_address = pubkey_to_address(to);
    // get the address of from
    let from_address = pubkey_to_address(&from.public());
    // get a random element for the nullifier secret
    let nullifier_secret = random_fr_ce();
    // derive the nullifier
    let hasher = poseidon_rs::Poseidon::new();
    let nullifier = hasher.hash(vec![nullifier_secret, from_address]).unwrap();
    // hash the auth message
    let auth_message = hasher.hash(vec![nullifier, to_address]).unwrap();
    // sign the auth message
    let auth_message = BigInt::from_bytes_le(Sign::Plus, &ff_ce_to_le_bytes(&auth_message)[..]);
    let auth_signature = from.sign(auth_message).unwrap();
    // return the auth signature and nullifier
    let nullifier_secret = convert_ff_ce_to_ff(&nullifier_secret);
    let nullifier = convert_ff_ce_to_ff(&nullifier);
    (auth_signature, nullifier_secret, nullifier)
}

/**
 * Generate a "scope" signature proving intent to participate in a degree chain
 *
 * @param from - the private key of the user generating the scope signature
 * @param scope - the scope address of the degree chain
 * @return - signature by "from" over the scope address
 */
pub fn sign_scope(from: &PrivateKey, scope: &Fr) -> Signature {
    let scope_message = BigInt::from_bytes_le(Sign::Plus, &scope.to_bytes()[..]);
    from.sign(scope_message).unwrap()
}
