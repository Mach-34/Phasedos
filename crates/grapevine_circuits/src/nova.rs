use super::{
    utils::read_public_params, DEFAULT_PUBLIC_PARAMS_PATH, DEFAULT_R1CS_PATH, Z0_PRIMARY,
    Z0_SECONDARY,
};
use crate::inputs::{GrapevineArtifacts, GrapevineInputs};
use babyjubjub_rs::Point;
use grapevine_common::{Fq, Fr, NovaProof, Params, G1, G2};
use nova_scotia::{
    circom::{circuit::R1CS, reader::load_r1cs},
    continue_recursive_circuit, create_recursive_circuit, FileLocation,
};
use nova_snark::errors::NovaError;
use std::{env::current_dir, path::PathBuf};

/**
 * Get public params for the grapevine circuit
 *
 * @param path - the relative path to the public params json file (if none use default)
 * @return  - the public parameters for proving/ verifying grapevine circuit execution
 */
pub fn get_public_params(path: Option<String>) -> Params {
    let root = current_dir().unwrap();
    let public_params_file = match path {
        Some(p) => root.join(p),
        None => root.join(DEFAULT_PUBLIC_PARAMS_PATH),
    };
    read_public_params::<G1, G2>(public_params_file.to_str().unwrap())
}

/**
 * Load the r1cs file for the grapevine circuit
 *
 * @param path - the relative path to the r1cs file of the grapevine circuit (if none use default)
 * @return - the r1cs file for the grapevine circuit
 */
pub fn get_r1cs(path: Option<String>) -> R1CS<Fr> {
    let root = current_dir().unwrap();
    let r1cs_file = match path {
        Some(p) => root.join(p),
        None => root.join(DEFAULT_R1CS_PATH),
    };
    load_r1cs::<G1, G2>(&FileLocation::PathBuf(r1cs_file))
}

/**
 * Start a nova IVC proof of for a degree of separation chain
 * This proof is an identity step (+ chaff step) and future iterations show degree from this identity
 *
 * @param artifacts - the loaded params and R1CS, as well as a path to the wasm file
 * @param inputs - the necessary inputs for a grapevine proof
 * @return - a proof of degree 0 (identity) of grapevine identity
 */
pub fn identity_proof(
    artifacts: &GrapevineArtifacts,
    inputs: &GrapevineInputs,
) -> Result<NovaProof, std::io::Error> {
    // get the formatted inputs to the circuit
    let private_inputs = inputs.fmt_circom();
    // create the degree proof
    create_recursive_circuit(
        artifacts.wasm_location.clone(),
        artifacts.r1cs.clone(),
        private_inputs.to_vec(),
        Z0_PRIMARY.clone(),
        &artifacts.params,
    )
}

/**
 * Continue a nova IVC proof ofr a degree of separation chain
 * This proof is a degree step (+ chaff step) showing degree of separation from an initial identity
 *
 * @param artifacts - the loaded params and R1CS, as well as a path to the wasm file
 * @param inputs - the necessary inputs for a grapevine proof
 * @param proof - the previous proof to build from
 * @param previous output - the previous output of the proof
 * @return - a proof of degree N from a grapevine identity
 */
pub fn degree_proof(
    artifacts: &GrapevineArtifacts,
    inputs: &GrapevineInputs,
    proof: &mut NovaProof,
    previous_output: &Vec<Fr>,
) -> Result<(), std::io::Error> {
    // get the formatted inputs to the circuit
    let private_inputs = inputs.fmt_circom();
    // create the degree proof
    continue_recursive_circuit(
        proof,
        previous_output.clone(),
        artifacts.wasm_location.clone(),
        artifacts.r1cs.clone(),
        private_inputs.to_vec(),
        Z0_PRIMARY.clone(),
        &artifacts.params,
    )
}

/**
 * Verify the correct execution of an IVC proof of the grapevine circuit
 *
 * @param proof - the proof to verify
 * @param public_params - the public params to use to verify the proof
 * @param iterations - the degree of separation proven (iterations should equal 2*degree + 2)
 * @return - the output of the proof if verified
 */
pub fn verify_grapevine_proof(
    proof: &NovaProof,
    public_params: &Params,
    degree: usize,
) -> Result<(Vec<Fr>, Vec<Fq>), NovaError> {
    proof.verify(public_params, degree * 2 + 2, &Z0_PRIMARY, &Z0_SECONDARY)
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::inputs::GrapevineOutputs;
    use crate::utils::{compress_proof, decompress_proof, read_proof, write_proof};
    use babyjubjub_rs::{new_key, Point, PrivateKey, Signature};
    use grapevine_common::compat::{convert_ff_ce_to_ff, ff_ce_to_le_bytes};
    use grapevine_common::utils::random_fr_ce;
    use grapevine_common::{
        account::GrapevineAccount,
        crypto::{pubkey_to_address, sign_auth, sign_scope},
        utils::random_fr,
    };
    use lazy_static::lazy_static;
    use nova_scotia::create_public_params;

    lazy_static! {
        pub static ref ARTIFACTS: GrapevineArtifacts = {
            // load params
            let params_path = String::from("circom/artifacts/public_params.json");
            let params = get_public_params(Some(params_path));
            // load r1cs
            let r1cs_path = String::from("circom/artifacts/grapevine.r1cs");
            let r1cs = get_r1cs(Some(r1cs_path));
            // set wasm path
            let wasm_location = FileLocation::PathBuf(current_dir().unwrap().join("circom/artifacts/grapevine.wasm"));
            // return artifacts struct
            GrapevineArtifacts { params, r1cs, wasm_location }
        };
        pub static ref ZERO: Fr = Fr::from(0);
        pub static ref KEYS: Vec<PrivateKey> = {
            let mut keys: Vec<PrivateKey> = vec![];
            for i in 0..10 {
                keys.push(new_key());
            }
            keys
        };
    }

    #[test]
    #[ignore]
    fn gen_public_params() {
        let root = current_dir().unwrap();
        let r1cs_path = String::from("circom/artifacts/grapevine.r1cs");
        let r1cs = get_r1cs(Some(r1cs_path));
        let public_params: Params = create_public_params(r1cs.clone());

        // save the full params
        let params_json = serde_json::to_string(&public_params).unwrap();
        let full_params_path = root.clone().join("public_params.json");
        std::fs::write(&full_params_path, &params_json).unwrap();
    }

    #[test]
    fn test_identity_proof() {
        // create inputs
        let identity_inputs = GrapevineInputs::identity_step(&KEYS[0]);
        // create proof
        let proof = identity_proof(&ARTIFACTS, &identity_inputs).unwrap();
        // verify proof
        let verified = verify_grapevine_proof(&proof, &ARTIFACTS.params, 0).unwrap();

        /// OUTPUT CHECK ///
        let outputs = GrapevineOutputs::try_from(verified.0).unwrap();
        // check obfuscate flag = 0
        assert_eq!(&*ZERO, &outputs.obfuscate);
        // check degree = 0
        assert_eq!(&*ZERO, &outputs.degree);
        // check scope and relation output (should be same)
        let expected_address = convert_ff_ce_to_ff(&pubkey_to_address(&KEYS[0].public()));
        assert_eq!(&expected_address, &outputs.scope);
        assert_eq!(&expected_address, &outputs.relation);
        // check all nullifiers = 0
        for i in 0..outputs.nullifiers.len() {
            assert_eq!(&*ZERO, &outputs.nullifiers[i]);
        }
    }

    #[test]
    fn test_degree_1() {
        // setup
        let identity_inputs = GrapevineInputs::identity_step(&KEYS[0]);
        let mut proof = identity_proof(&ARTIFACTS, &identity_inputs).unwrap();
        // get previous inputs for proof
        let verified = verify_grapevine_proof(&proof, &ARTIFACTS.params, 0).unwrap();
        let outputs = GrapevineOutputs::try_from(verified.0).unwrap();
        // generate auth signature and nullifier
        let (auth_signature, _, nullifier) = sign_auth(&KEYS[0], &KEYS[1].public());
        // generate the scope signature
        let scope_signature = sign_scope(&KEYS[1], &outputs.scope);
        // generate degree inputs
        let degree_inputs = GrapevineInputs::degree_step(
            &KEYS[1],
            &KEYS[0].public(),
            &nullifier,
            &outputs.scope,
            &auth_signature,
        );
        // prove degree 1 separation from identity
        degree_proof(
            &ARTIFACTS,
            &degree_inputs,
            &mut proof,
            &outputs.try_into().unwrap(),
        )
        .unwrap();

        // verify degree 1 prof
        let verified = verify_grapevine_proof(&proof, &ARTIFACTS.params, 1).unwrap();
        // check outputs
        let outputs = GrapevineOutputs::try_from(verified.0).unwrap();
        // check obfuscate flag = 0
        assert_eq!(&*ZERO, &outputs.obfuscate);
        // check degree = 1
        assert_eq!(&Fr::from(1), &outputs.degree);
        // check scope = key[0] address
        let expected_scope = convert_ff_ce_to_ff(&pubkey_to_address(&KEYS[0].public()));
        assert_eq!(&expected_scope, &outputs.scope);
        // check relation = key[1] address
        let expected_relation = convert_ff_ce_to_ff(&pubkey_to_address(&KEYS[1].public()));
        assert_eq!(&expected_relation, &outputs.relation);
        // check 1st nullifier = given nullifier
        assert_eq!(&nullifier, &outputs.nullifiers[0]);
        // check all other nullifiers are 0
        for i in 1..outputs.nullifiers.len() {
            assert_eq!(&*ZERO, &outputs.nullifiers[i]);
        }
    }

    #[test]
    fn test_degree_8() {
        // identity proof
        println!("Proving Identity (Degree 0)");
        let identity_inputs = GrapevineInputs::identity_step(&KEYS[0]);
        let mut proof = identity_proof(&ARTIFACTS, &identity_inputs).unwrap();
        let verified = verify_grapevine_proof(&proof, &ARTIFACTS.params, 0).unwrap();
        let mut outputs = GrapevineOutputs::try_from(verified.0).unwrap();
        // iterate through degree proofs
        let expected_scope = convert_ff_ce_to_ff(&pubkey_to_address(&KEYS[0].public()));
        let mut nullifiers: Vec<Fr> = vec![];
        for i in 0..8 {
            println!("Proving {} degree(s) of separation from identity", i + 1);
            let relation = &KEYS[i];
            let prover = &KEYS[i + 1];
            // generate inputs
            let (auth_signature, _, nullifier) = sign_auth(relation, &prover.public());
            let scope_signature = sign_scope(prover, &outputs.scope);
            let degree_inputs = GrapevineInputs::degree_step(
                prover,
                &relation.public(),
                &nullifier,
                &outputs.scope,
                &auth_signature,
            );
            nullifiers.push(nullifier.clone());
            // prove degree + chaff IVC steps from previous proof
            degree_proof(
                &ARTIFACTS,
                &degree_inputs,
                &mut proof,
                &outputs.try_into().unwrap(),
            )
            .unwrap();
            // verify degree 1 prof
            let verified = verify_grapevine_proof(&proof, &ARTIFACTS.params, i + 1).unwrap();
            // check outputs
            outputs = GrapevineOutputs::try_from(verified.0).unwrap();
            // check obfuscate flag = 0
            assert_eq!(&*ZERO, &outputs.obfuscate);
            // check degree
            assert_eq!(&Fr::from(i as u64 + 1), &outputs.degree);
            // check scope = key[0] address
            assert_eq!(&expected_scope, &outputs.scope);
            // check relation = key[1] address
            let expected_relation = convert_ff_ce_to_ff(&pubkey_to_address(&KEYS[i + 1].public()));
            assert_eq!(&expected_relation, &outputs.relation);
            // check all other nullifiers are 0
            for j in 0..8 {
                if (j < i + 1) {
                    assert_eq!(&nullifiers[j], &outputs.nullifiers[j]);
                } else {
                    assert_eq!(&*ZERO, &outputs.nullifiers[j]);
                }
            }
        }
    }

    #[ignore]
    #[test]
    fn test_nonzero_starting_inputs() {
        unimplemented!()
    }

    #[ignore]
    #[test]
    fn test_bad_auth_signature_from() {}

    #[ignore]
    #[test]
    fn test_bad_auth_signature_to() {}

    #[ignore]
    #[test]
    fn test_bad_auth_signature_nullifier() {}

    #[ignore]
    #[test]
    fn test_bad_scope_signature_pubkey() {}

    #[ignore]
    #[test]
    fn test_bad_scope_signature_scope() {}

    #[ignore]
    #[test]
    fn test_no_degree_9() {}

    // #[test]
    // fn test_continued_fs() {
    //     // test recursively proving degree 1 and 2 where proof 1 is saved to fs then read in for proof 2
    //     // define inputs
    //     let phrase = String::from("Filesystem filesystem system of a file");
    //     let accounts = vec!["mach34", "jp4g", "ianb", "ct"]
    //         .iter()
    //         .map(|s| GrapevineAccount::new(String::from(*s)))
    //         .collect::<Vec<GrapevineAccount>>();
    //     let mut auth_signatures = vec![[random_fr(), random_fr(), random_fr()]];

    //     for i in 1..accounts.len() {
    //         let recipient_pubkey = accounts[i].pubkey();
    //         let auth_signature = accounts[i - 1].generate_auth_signature(recipient_pubkey);
    //         let decrypted = accounts[i].decrypt_auth_signature(auth_signature);
    //         auth_signatures.push(decrypted.fmt_circom());
    //     }

    //     let pubkeys = accounts
    //         .iter()
    //         .map(|acc| acc.pubkey())
    //         .collect::<Vec<Point>>();

    //     // define paths
    //     let params_path = String::from("circom/artifacts/public_params.json");
    //     let r1cs_path = String::from("circom/artifacts/grapevine.r1cs");
    //     let wc_path = current_dir()
    //         .unwrap()
    //         .join("circom/artifacts/grapevine_js/grapevine.wasm");

    //     // load public params and r1cs
    //     let r1cs = get_r1cs(Some(r1cs_path));
    //     let public_params = get_public_params(Some(params_path));

    //     // PROVE DEGREE 1 //
    //     let degree = 1;
    //     let proof = nova_proof(
    //         wc_path.clone(),
    //         &r1cs,
    //         &public_params,
    //         &phrase,
    //         &vec![pubkeys[0].clone()],
    //         &vec![auth_signatures[0]],
    //     )
    //     .unwrap();

    //     let res = verify_nova_proof(&proof, &public_params, 1 + degree * 2).unwrap();
    //     let z0_last = res.0; // step_out for the circuit execution
    //     assert!(z0_last[0].eq(&Fr::from(degree as u64)));

    //     // safe to fs
    //     let proof_path = std::env::current_dir()
    //         .unwrap()
    //         .join(format!("grapevine_degree_{}.gz", degree));
    //     write_proof(&proof, proof_path.clone());

    //     // PROVE DEGREE 2 //
    //     // read proof from fs
    //     let mut proof = read_proof(proof_path.clone());
    //     // get z0_last
    //     let z0_last = verify_nova_proof(&proof, &public_params, 1 + degree * 2)
    //         .unwrap()
    //         .0;
    //     // prove second degree
    //     let degree = 2;
    //     continue_nova_proof(
    //         &pubkeys[1],
    //         &auth_signatures[1],
    //         &mut proof,
    //         z0_last,
    //         wc_path.clone(),
    //         &r1cs,
    //         &public_params,
    //     )
    //     .unwrap();
    //     let res = verify_nova_proof(&proof, &public_params, 1 + degree * 2).unwrap();
    //     let z0_last = res.0;
    //     assert!(z0_last[0].eq(&Fr::from(degree as u64)));
    // }

    // #[test]
    // fn test_compression() {
    //     // Compute a proof
    //     let phrase: String = String::from("There's no place like home");
    //     let account = GrapevineAccount::new(String::from("mach34"));
    //     let auth_signatures = vec![[random_fr(), random_fr(), random_fr()]];
    //     let params_path = String::from("circom/artifacts/public_params.json");
    //     let r1cs_path = String::from("circom/artifacts/grapevine.r1cs");
    //     let wc_path = current_dir()
    //         .unwrap()
    //         .join("circom/artifacts/grapevine_js/grapevine.wasm");
    //     let r1cs = get_r1cs(Some(r1cs_path));
    //     let public_params = get_public_params(Some(params_path));
    //     let proof = nova_proof(
    //         wc_path,
    //         &r1cs,
    //         &public_params,
    //         &phrase,
    //         &vec![account.pubkey()],
    //         &auth_signatures,
    //     )
    //     .unwrap();

    //     // compress the proof
    //     let compressed_proof = compress_proof(&proof);

    //     // compare proof sizes when compressed vs uncompressed
    //     let serialized = serde_json::to_string(&proof).unwrap().as_bytes().to_vec();
    //     println!("Uncompressed proof size: {}", serialized.len());
    //     println!("Compressed proof size: {}", compressed_proof.len());

    //     // decompress the proof
    //     let decompressed_proof = decompress_proof(&compressed_proof[..]);

    //     // verify the compressed then uncompressed proof
    //     let iterations = 3;
    //     verify_nova_proof(&decompressed_proof, &public_params, iterations).unwrap();
    // }
}
