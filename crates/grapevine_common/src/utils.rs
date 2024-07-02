use crate::{compat::ff_ce_from_le_bytes, Fr, MAX_SECRET_CHARS, MAX_USERNAME_CHARS, SECRET_FIELD_LENGTH};
use babyjubjub_rs::Fr as Fr_ce;
use std::error::Error;

/**
 * Generates a new stringified random bn254 field element
 *
 * @return - a stringified random field element
 */
pub fn random_fr() -> Fr {
    ff::Field::random(rand::rngs::OsRng)
}

pub fn random_fr_ce() -> Fr_ce {
    ff_ce_from_le_bytes(random_fr().to_bytes())
}

/**
 * Converts a given word to array of 6 field elements
 * @dev split into 31-byte strings to fit in finite field and pad with 0's where necessary
 *
 * @param phrase - the string entered by user to compute hash for (will be length checked)
 * @return - array of 6 Fr elements
 */
pub fn convert_phrase_to_fr(
    phrase: &String,
) -> Result<[[u8; 32]; SECRET_FIELD_LENGTH], Box<dyn Error>> {
    // check
    if phrase.len() > MAX_SECRET_CHARS {
        return Err("Phrase must be <= 180 characters".into());
    }

    let mut chunks: [[u8; 32]; SECRET_FIELD_LENGTH] = Default::default();
    for i in 0..SECRET_FIELD_LENGTH {
        let start = i * 31;
        let end = (i + 1) * 31;
        let mut chunk: [u8; 32] = [0; 32];
        if start >= phrase.len() {
        } else if end > phrase.len() {
            chunk[1..(phrase.len() - start + 1)].copy_from_slice(&phrase.as_bytes()[start..]);
        } else {
            chunk[1..32].copy_from_slice(&phrase.as_bytes()[start..end]);
        }
        chunk.reverse();
        chunks[i] = chunk;
    }
    // format!("0x{}", hex::encode(chunk));
    Ok(chunks)
}

/**
 * Converts a given username to a field element
 *
 * @param username - the username to convert to utf8 and into field element
 * @return - the username serialied into the field element
 */
pub fn convert_username_to_fr(username: &String) -> Result<[u8; 32], Box<dyn Error>> {
    if username.len() > MAX_USERNAME_CHARS {
        return Err("Username must be <= 30 characters".into());
    }
    let mut bytes: [u8; 32] = [0; 32];
    bytes[1..(username.len() + 1)].copy_from_slice(&username.as_bytes()[..]);
    bytes.reverse();
    //    Ok(format!("0x{}", hex::encode(bytes)))
    Ok(bytes)
}

// TODO: Add documentation
pub fn to_array_32(mut vec: Vec<u8>) -> [u8; 32] {
    // Ensure the vector is either 31 or 32 bytes long
    assert!(
        vec.len() == 31 || vec.len() == 32,
        "Vec must be either 31 or 32 bytes long"
    );

    // Pad with a zero byte if the vector is 31 bytes long
    if vec.len() == 31 {
        vec.push(0);
    }

    // Convert the vector to a boxed slice and then try into a fixed-size array
    let boxed_slice = vec.into_boxed_slice();
    let boxed_array: Box<[u8; 32]> = match boxed_slice.try_into() {
        Ok(array) => array,
        Err(_) => unreachable!("The length should be 32 at this point"),
    };

    // Unbox the array to get [u8; 32]
    *boxed_array
}
