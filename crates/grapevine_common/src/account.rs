use crate::auth_signature::{AuthSignature, AuthSignatureEncrypted, AuthSignatureEncryptedUser};
use crate::compat::{convert_ff_ce_to_ff, convert_ff_to_ff_ce, ff_ce_to_le_bytes};
use crate::crypto::{gen_aes_key, new_private_key, nonce_hash, pubkey_to_address};
use crate::http::requests::{CreateUserRequest, GetNonceRequest, NewRelationshipRequest};
use crate::utils::{convert_username_to_fr, random_fr};
use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use babyjubjub_rs::{Point, PrivateKey, Signature};
use num_bigint::{BigInt, Sign};
use poseidon_rs::{Fr, Poseidon};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

type Aes128CbcEnc = cbc::Encryptor<aes::Aes128>;
type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;
#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct GrapevineAccount {
    username: String,
    private_key: [u8; 32],
    nonce: u64,
}

impl GrapevineAccount {
    /**
     * Generates a new account
     *
     * @param username - the username to associate with this account
     * @returns - the new account with an autogenerated private key
     */
    pub fn new(username: String) -> GrapevineAccount {
        let private_key = new_private_key();
        GrapevineAccount {
            username,
            private_key,
            nonce: 0,
        }
    }

    /**
     * Test function to allow manual specification of account
     */
    pub fn from_repr(username: String, private_key: [u8; 32], nonce: u64) -> Self {
        Self {
            username,
            private_key,
            nonce,
        }
    }

    /// PERSISTENCE METHODS ///

    /**
     * Reads an account saved to the filesystem
     */
    pub fn from_fs(path: PathBuf) -> Result<GrapevineAccount, serde_json::Error> {
        let account = std::fs::read_to_string(path).unwrap();
        serde_json::from_str(&account)
    }

    pub fn save(&self, path: PathBuf) -> Result<(), std::io::Error> {
        let account = serde_json::to_string(&self).unwrap();
        std::fs::write(path, account)
    }

    /// NONCE METHODS ///

    /**
     * Increment nonce by 1 for normal actions
     *
     * @param save - if some, path to save the account to after incrementing nonce
     */
    pub fn increment_nonce(&mut self, save: Option<PathBuf>) -> Result<(), std::io::Error> {
        self.nonce += 1;
        if save.is_some() {
            return self.save(save.unwrap());
        }
        Ok(())
    }

    /**
     * Set the nonce manually in the event nonce is desynchronized from server
     *
     * @param nonce - the new nonce to set for the account\
     * @param save - if some, path to save the account to after incrementing nonce
     */
    pub fn set_nonce(&mut self, nonce: u64, save: Option<PathBuf>) -> Result<(), std::io::Error> {
        self.nonce = nonce;
        if save.is_some() {
            return self.save(save.unwrap());
        }
        Ok(())
    }

    /// AUTH SIGNATURE METHODS ///

    /**
     * Decrypt an encrypted auth signature that should be encrypted with this account's public key
     *
     * @param message - the encrypted auth signature
     * @returns - the decrypted auth signature
     */
    pub fn decrypt_auth_signature(&self, message: AuthSignatureEncrypted) -> AuthSignature {
        message.decrypt(self.private_key())
    }

    /**
     * Generates encrypted auth signature over recipient private key
     *
     * @param message - the encrypted auth signature
     * @returns - the decrypted auth signature
     */
    pub fn generate_auth_signature(
        &self,
        recipient: Point,
        nullifier: Fr,
    ) -> AuthSignatureEncrypted {
        // generate recipient address from recipient pubkey
        let address = pubkey_to_address(&recipient);
        let hasher = Poseidon::new();
        let hash = hasher.hash(vec![nullifier, address]).unwrap();

        // sign pubkey hash
        let message = BigInt::from_bytes_le(Sign::Plus, &ff_ce_to_le_bytes(&hash));
        let signature: Signature = self.private_key().sign(message).unwrap();

        AuthSignatureEncrypted::new(
            self.username.clone(),
            signature,
            convert_ff_ce_to_ff(&nullifier),
            recipient,
        )
    }

    /// PHRASE ENCRYPTION METHODS ///

    /**
     * Encrypt a phrase for this account
     */
    pub fn encrypt_phrase(&self, phrase: &String) -> [u8; 192] {
        // convert phrase to binary
        let mut bytes = phrase.as_bytes().to_vec();
        bytes.resize(180, 0);
        let mut buf = [0u8; 192];
        buf[..bytes.len()].copy_from_slice(&bytes);
        // generate encryption key
        let (aes_key, aes_iv) = gen_aes_key(self.private_key(), self.pubkey());
        // encrypt padded phrase
        Aes128CbcEnc::new(aes_key[..].into(), aes_iv[..].into())
            .encrypt_padded_mut::<Pkcs7>(&mut buf, bytes.len())
            .unwrap()
            .try_into()
            .unwrap()
    }

    /**
     * Decrypt a phrase for this account
     */
    pub fn decrypt_phrase(&self, ciphertext: &[u8; 192]) -> String {
        // derive asymmetric key key
        let (aes_key, aes_iv) = gen_aes_key(self.private_key(), self.pubkey());
        // decrypt ciphertext
        let mut buf = ciphertext.clone();
        let ptr: [u8; 180] = Aes128CbcDec::new(aes_key[..].into(), aes_iv[..].into())
            .decrypt_padded_mut::<Pkcs7>(&mut buf)
            .unwrap()
            .try_into()
            .unwrap();
        // return the string
        let end = ptr.iter().position(|&r| r == 0).unwrap_or(ptr.len());
        String::from_utf8(ptr[..end].to_vec()).unwrap()
    }

    /**
     * Generates a nullifier for use in a relationship
     */
    pub fn generate_nullifier(&self) -> (Fr, [u8; 48]) {
        let nullifier_secret = convert_ff_to_ff_ce(&random_fr());

        let address = pubkey_to_address(&self.pubkey()); // TODO: Make address helper function

        let hasher = Poseidon::new();
        let nullifier = hasher.hash(vec![nullifier_secret, address]).unwrap();

        let secret_bytes = ff_ce_to_le_bytes(&nullifier_secret);
        // encrypt the nullifier secret to issuer
        let (aes_key, aes_iv) = gen_aes_key(self.private_key(), self.pubkey());
        let mut buf = [0u8; 48];
        buf[..secret_bytes.len()].copy_from_slice(&secret_bytes);
        let encrypted_nullifier_secret: [u8; 48] =
            Aes128CbcEnc::new(aes_key[..].into(), aes_iv[..].into())
                .encrypt_padded_mut::<Pkcs7>(&mut buf, secret_bytes.len())
                .unwrap()
                .try_into()
                .unwrap();
        (nullifier, encrypted_nullifier_secret)
    }

    /// SIGNING METHODS ///

    /**
     * Produce a signature over the username of this account
     *
     * @returns - the signature over the username
     */
    pub fn sign_username(&self) -> Signature {
        let message = BigInt::from_bytes_le(
            Sign::Plus,
            &convert_username_to_fr(&self.username).unwrap()[..],
        );
        self.private_key().sign(message).unwrap()
    }

    /**
     * Produce a signature over the sha256 hash H|username, nonce| of this account
     *
     * @returns - the signature authorizing arbitrary gated http actions
     */
    pub fn sign_nonce(&self) -> Signature {
        let message =
            BigInt::from_bytes_le(Sign::Plus, &nonce_hash(&self.username, self.nonce)[..]);
        self.private_key().sign(message).unwrap()
    }

    /// HTTP REQUEST BODY CONSTRUCTORS ///

    /**
     * Create the http request body for creating a new user in the Grapevine service
     *
     * @param proof - the compressed proof of identity (degree 0) for this user
     *
     * @returns - the CreateUserRequest authorizing a new user to be added to Grapevine service
     */
    pub fn create_user_request(&self, proof: Vec<u8>) -> CreateUserRequest {
        CreateUserRequest {
            username: self.username.clone(),
            pubkey: self.pubkey().compress(),
            proof,
        }
    }

    /**
     * Create the http request body for creating adding a relationship to another user in the Grapevine Service
     *
     * @param username - the username of the target user adding you as a relationship
     * @param pubkey - the public key of the target user adding you as a relationship
     * @returns - the NewRelationshipRequest containing encrypted auth signature for target to use
     */
    pub fn new_relationship_request(
        &self,
        username: &String,
        pubkey: &Point,
    ) -> NewRelationshipRequest {
        // generate a nullifier for relationship
        let (nullifier, encrypted_nullifier_secret) = self.generate_nullifier();
        // encrypt the auth signature with the target pubkey
        let encrypted_auth_signature = self.generate_auth_signature(pubkey.clone(), nullifier);

        let encrypted_nullifier: [u8; 48] = [0u8; 48]; // TODO: Encrypt nullifier
                                                       // return the New Relationship http request struct
        NewRelationshipRequest {
            encrypted_nullifier: encrypted_nullifier,
            encrypted_nullifier_secret: encrypted_nullifier_secret,
            to: username.clone(),
            ephemeral_key: encrypted_auth_signature.ephemeral_key,
            encrypted_auth_signature: encrypted_auth_signature.ciphertext,
        }
    }

    /**
     * Create the http request body for getting a nonce from the Grapevine service
     *
     * @returns - the GetNonceRequest containing the signature over the username
     */
    pub fn get_nonce_request(&self) -> GetNonceRequest {
        GetNonceRequest {
            username: self.username.clone(),
            signature: self.sign_username().compress(),
        }
    }

    /// GETTERS ///

    /** Return the username associated with this account */
    pub fn username(&self) -> &String {
        &self.username
    }

    /** Return the Baby Jubjub EdDSA public key associated with this account */
    pub fn pubkey(&self) -> Point {
        PrivateKey::import(self.private_key.to_vec())
            .unwrap()
            .public()
    }

    /** Return the raw bytes of the Baby Jubjub EdDSA private key associated with this account */
    pub fn private_key_raw(&self) -> &[u8; 32] {
        &self.private_key
    }

    /** Return the Baby Jubjub EdDSA private key associated with this account */
    pub fn private_key(&self) -> PrivateKey {
        PrivateKey::import(self.private_key.to_vec()).unwrap()
    }

    /** Return the current nonce for this account */
    pub fn nonce(&self) -> u64 {
        self.nonce
    }
}

#[cfg(test)]
mod test {

    use super::*;

    #[test]
    fn test_serialize() {
        let username = String::from("JP4G");
        let account = GrapevineAccount::new(username);
        let json = serde_json::to_string(&account).unwrap();
        let deserialized = serde_json::from_str::<GrapevineAccount>(&json).unwrap();
        let deserialized_key = hex::encode(deserialized.private_key);
        assert_eq!(deserialized_key, hex::encode(account.private_key));
    }

    #[test]
    fn test_phrase_encryption() {
        let username = String::from("JP4G");
        let account = GrapevineAccount::new(username);
        let phrase = String::from("This is a test phrase");
        let ciphertext = account.encrypt_phrase(&phrase);
        let decrypted = account.decrypt_phrase(&ciphertext);
        assert_eq!(decrypted, phrase);
    }
}
