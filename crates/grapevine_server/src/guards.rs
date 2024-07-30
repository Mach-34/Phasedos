use crate::catchers::ErrorMessage;
use crate::mongo::GrapevineDB;
use babyjubjub_rs::{decompress_point, decompress_signature, verify};
use grapevine_common::crypto::nonce_hash;
use grapevine_common::errors::GrapevineError;
use num_bigint::{BigInt, Sign};
use rocket::{
    http::Status,
    outcome::Outcome::{Error as Failure, Success},
    request::{FromRequest, Outcome, Request},
    State,
};

/** A username passed through header that passes the signed nonce check */
#[derive(Debug, Clone)]
pub struct AuthenticatedUser(pub String);

#[rocket::async_trait]
impl<'r> FromRequest<'r> for AuthenticatedUser {
    type Error = ErrorMessage;

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        // Connect to mongodb
        let mongo = match request.guard::<&State<GrapevineDB>>().await {
            Success(db) => db,
            _ => {
                request.local_cache(|| {
                    ErrorMessage(Some(GrapevineError::MongoError(String::from(
                        "Error connecting to database",
                    ))))
                });
                return Failure((Status::InternalServerError, ErrorMessage(None)));
            }
        };
        // Check for X-Username header
        let username = match request.headers().get_one("X-Username") {
            Some(username) => String::from(username),
            None => {
                request.local_cache(|| {
                    ErrorMessage(Some(GrapevineError::HeaderError(String::from(
                        "couldn't find X-Username",
                    ))))
                });
                return Failure((Status::BadRequest, ErrorMessage(None)));
            }
        };
        // Check for X-Authorization header (signature over nonce)
        let signature = match request.headers().get_one("X-Authorization") {
            Some(data) => {
                // attempt to parse the signature
                let bytes: [u8; 64] = hex::decode(data).unwrap().try_into().unwrap();
                match decompress_signature(&bytes) {
                    Ok(signature) => signature,
                    Err(_) => {
                        request.local_cache(|| {
                            ErrorMessage(Some(GrapevineError::HeaderError(String::from(
                                "couldn't parse X-Authorization",
                            ))))
                        });
                        return Failure((Status::BadRequest, ErrorMessage(None)));
                    }
                }
            }
            None => {
                request.local_cache(|| {
                    ErrorMessage(Some(GrapevineError::HeaderError(String::from(
                        "couldn't find X-Authorization",
                    ))))
                });
                return Failure((Status::BadRequest, ErrorMessage(None)));
            }
        };
        // Retrieve nonce from database
        let (nonce, pubkey) = match mongo.get_nonce(&username).await {
            Some(data) => data,
            None => {
                request.local_cache(|| ErrorMessage(Some(GrapevineError::UserNotFound(username))));
                return Failure((Status::NotFound, ErrorMessage(None)));
            }
        };
        // convert pubkey to bjj point (assumes won't fail due to other checks)
        let pubkey = decompress_point(pubkey).unwrap();
        // Take the sha256 hash of the nonce and username, and convert to bjj message format
        let message = BigInt::from_bytes_le(Sign::Plus, &nonce_hash(&username, nonce));
        // Check that signature matches expected nonce/ username hash
        match verify(pubkey, signature, message) {
            true => (),
            false => {
                request.local_cache(|| {
                    ErrorMessage(Some(GrapevineError::Signature(String::from(
                        "Failed to verify nonce signature",
                    ))))
                });
                return Failure((Status::Unauthorized, ErrorMessage(None)));
            }
        };
        // Increment nonce in database
        match mongo.increment_nonce(&username).await {
            Ok(_) => Success(AuthenticatedUser(username)),
            Err(_) => {
                request.local_cache(|| {
                    ErrorMessage(Some(GrapevineError::MongoError(String::from(
                        "Error incrementing nonce",
                    ))))
                });
                return Failure((Status::InternalServerError, ErrorMessage(None)));
            }
        }
    }
}
