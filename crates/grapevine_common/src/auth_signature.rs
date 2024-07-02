use crate::compat::{convert_ff_ce_to_ff, convert_ff_to_ff_ce, ff_ce_to_le_bytes};
use crate::Fr;
use crate::{crypto::gen_aes_key, utils::to_array_32};
use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use babyjubjub_rs::{decompress_signature, Point, PrivateKey, Signature};
use ff::PrimeField;
use serde::{Deserialize, Serialize};
type Aes128CbcEnc = cbc::Encryptor<aes::Aes128>;
type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;

/**
 * Encrypted version of an auth signature with the necessary info for the recipient to decrypt it
 */
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AuthSignatureEncrypted {
    pub username: String,
    pub recipient: [u8; 32],
    pub ephemeral_key: [u8; 32],
    #[serde(with = "serde_bytes")]
    pub nullifier: [u8; 48],
    #[serde(with = "serde_bytes")]
    pub ciphertext: [u8; 80],
}

/**
 * The confidential AuthSignature used when proving a degree of separation in Grapevine
 */
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AuthSignature {
    pub username: String,
    #[serde(with = "serde_bytes")]
    pub nullifier: [u8; 32],
    #[serde(with = "serde_bytes")]
    pub auth_signature: [u8; 64], // compressed form of auth signature
}

impl AuthSignature {
    // TODO: Add documentation
    pub fn fmt_circom(&self) -> [Fr; 3] {
        // decompress signature
        let decompressed = decompress_signature(&self.auth_signature).unwrap();
        // convert s value of signature to Fr
        let s_bytes = to_array_32(decompressed.s.to_bytes_le().1);
        [
            convert_ff_ce_to_ff(&decompressed.r_b8.x),
            convert_ff_ce_to_ff(&decompressed.r_b8.y),
            Fr::from_repr(s_bytes).unwrap(),
        ]
    }
}

pub trait AuthSignatureEncryptedUser {
    /**
     * Create a new encrypted auth signature
     *
     * @param username - the username associated with this auth signature
     * @param auth_signature - the auth signature over user's pubkey
     * @param recipient- the bjj pubkey of the recipient of the auth signature
     * @returns - encrypted auth signature
     */
    fn new(username: String, auth_signature: Signature, nullifier: Fr, recipient: Point) -> Self;

    /**
     * Decrypts an encrypted AuthSignature
     *
     * @param recipient - the private key of the recipient of the auth signature
     * @returns - the decrypted auth signature
     */
    fn decrypt(&self, recipient: PrivateKey) -> AuthSignature;
}

impl AuthSignatureEncryptedUser for AuthSignatureEncrypted {
    fn new(username: String, signature: Signature, nullifier: Fr, recipient: Point) -> Self {
        // generate a new ephemeral keypair
        let ephm_sk = babyjubjub_rs::new_key();
        let ephm_pk = ephm_sk.public().compress();
        // compute the aes-cbc-128 key
        let (aes_key, aes_iv) = gen_aes_key(ephm_sk, recipient.clone());
        let nullifier_bytes = ff_ce_to_le_bytes(&convert_ff_to_ff_ce(&nullifier)); // TODO: Change this garbage

        // encrypt the auth signature
        let plaintext = signature.compress();
        let mut sig_buf = [0u8; 80];
        sig_buf[..plaintext.len()].copy_from_slice(&plaintext);
        let ciphertext: [u8; 80] = Aes128CbcEnc::new(aes_key[..].into(), aes_iv[..].into())
            .encrypt_padded_mut::<Pkcs7>(&mut sig_buf, plaintext.len())
            .unwrap()
            .try_into()
            .unwrap();

        let mut null_buf = [0u8; 48];
        null_buf[..nullifier_bytes.len()].copy_from_slice(&nullifier_bytes);
        let encrypted_nullifier: [u8; 48] =
            Aes128CbcEnc::new(aes_key[..].into(), aes_iv[..].into())
                .encrypt_padded_mut::<Pkcs7>(&mut null_buf, nullifier_bytes.len())
                .unwrap()
                .try_into()
                .unwrap();

        // return the encrypted auth signature
        Self {
            username,
            recipient: recipient.compress(),
            ephemeral_key: ephm_pk,
            ciphertext: ciphertext,
            nullifier: encrypted_nullifier,
        }
    }

    fn decrypt(&self, recipient: PrivateKey) -> AuthSignature {
        // compute the aes-cbc-128 key
        let ephm_pk = babyjubjub_rs::decompress_point(self.ephemeral_key).unwrap();
        let (aes_key, aes_iv) = gen_aes_key(recipient, ephm_pk);

        // decrypt the auth signature
        let mut sig_buf = self.ciphertext;
        let auth_signature: [u8; 64] = Aes128CbcDec::new(aes_key[..].into(), aes_iv[..].into())
            .decrypt_padded_mut::<Pkcs7>(&mut sig_buf)
            .unwrap()
            .try_into()
            .unwrap();

        // decrypt the nullifier
        let mut null_buf = self.nullifier;
        let nullifier: [u8; 32] = Aes128CbcDec::new(aes_key[..].into(), aes_iv[..].into())
            .decrypt_padded_mut::<Pkcs7>(&mut null_buf)
            .unwrap()
            .try_into()
            .unwrap();

        AuthSignature {
            username: self.username.clone(),
            auth_signature,
            nullifier,
        }
    }
}

#[cfg(test)]
mod test {
    use num_bigint::{BigInt, Sign};
    use poseidon_rs::Poseidon;

    use super::*;
    use crate::{compat::ff_ce_to_le_bytes, utils::random_fr};
    #[test]
    fn integrity_test() {
        // setup
        let username = String::from("JP4G");
        let sender_sk = babyjubjub_rs::new_key();
        let recipient_sk = babyjubjub_rs::new_key();
        let recipient_pk = recipient_sk.public();

        // hash recipient pubkey
        let poseidon = Poseidon::new();
        let hash = poseidon.hash(vec![recipient_pk.x, recipient_pk.y]).unwrap();

        // sign pubkey hash
        let msg = BigInt::from_bytes_le(Sign::Plus, &ff_ce_to_le_bytes(&hash));
        let auth_signature = sender_sk.sign(msg).unwrap();

        // generate relationship nullifier
        // TODO: Use random nullifier for now
        let nullifier = random_fr();

        // create encrypted auth signature
        let encrypted_auth_signature =
            AuthSignatureEncrypted::new(username, auth_signature.clone(), nullifier, recipient_pk);
        // decrypt the auth signature
        let decrypted_auth_signature = encrypted_auth_signature.decrypt(recipient_sk);
        // check that the auth signature is the same
        assert!(decrypted_auth_signature
            .auth_signature
            .eq(&auth_signature.compress()));
        println!("auth_signature_1 {:?}", auth_signature);
        println!(
            "auth_signature_2 {:?}",
            decrypted_auth_signature.auth_signature
        );
    }

    #[test]
    fn serde_test() {
        // setup
        let username = String::from("JP4G");
        let sender_sk = babyjubjub_rs::new_key();
        let recipient_sk = babyjubjub_rs::new_key();
        let recipient_pk = recipient_sk.public();

        // hash recipient pubkey
        let poseidon = Poseidon::new();
        let hash = poseidon.hash(vec![recipient_pk.x, recipient_pk.y]).unwrap();

        // sign pubkey hash
        let msg = BigInt::from_bytes_le(Sign::Plus, &ff_ce_to_le_bytes(&hash));
        let auth_signature = sender_sk.sign(msg).unwrap();

        // TODO: Use random nullifier for now
        let nullifier = random_fr();

        // create encrypted auth signature
        let encrypted_auth_signature =
            AuthSignatureEncrypted::new(username, auth_signature.clone(), nullifier, recipient_pk);
        // serialize to json
        let json = serde_json::to_string(&encrypted_auth_signature).unwrap();
        // deserialize from json
        let deserialized = serde_json::from_str::<AuthSignatureEncrypted>(&json).unwrap();
        let decrypted_auth_signature = deserialized.decrypt(recipient_sk);
        // check that the auth signature is the same
        assert!(decrypted_auth_signature
            .auth_signature
            .eq(&auth_signature.compress()));
    }
}
