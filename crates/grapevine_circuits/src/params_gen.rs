use flate2::{write::GzEncoder, Compression};
use grapevine_common::{Params, G1, G2};
use nova_scotia::{circom::reader::load_r1cs, create_public_params, FileLocation, C1, C2, S};
use std::{env, path::Path, io::Write};

// Utility for building circuit artifacts, assumes grapevine/scripts/compile.sh has already run
#[cfg(not(target_family = "wasm"))]
pub fn main() {
    // check for the existence of the artifacts directory in the current dir
    let current_dir = env::current_dir().expect("Failed to get current directory");
    let artifacts_path = current_dir.join("./crates/grapevine_circuits/circom/artifacts");
    if !artifacts_path.exists() {
        panic!("Run ./scripts/compile.sh first")
    };

    // check for the existence of the chunked params directory in artifacts
    let chunked_params_path = artifacts_path.join("./params_chunked");
    if !chunked_params_path.exists() {
        std::fs::create_dir(&chunked_params_path)
            .expect("Unable to create chunked params directory");
    }

    // generate the public parameters from the r1cs
    let r1cs_path = artifacts_path.join("./grapevine.r1cs");
    let r1cs = load_r1cs::<G1, G2>(&FileLocation::PathBuf(r1cs_path));
    let public_params: Params = create_public_params(r1cs.clone());

    // write the full public params to the fs
    let params_path = artifacts_path.join("./public_params.json");
    let params_json = serde_json::to_string(&public_params).unwrap();
    std::fs::write(&params_path, &params_json).expect("Unable to write public params");

    // compress the public params
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(&params_json.as_bytes()).unwrap();
    let compressed_params = encoder.finish().unwrap();

    // chunk the params and save to fs
    let chunk_size = (compressed_params.len() + 9) / 10;
    let chunks: Vec<&[u8]> = compressed_params.chunks(chunk_size).collect();
    for (i, chunk) in chunks.iter().enumerate() {
        let chunk_path = chunked_params_path.join(format!("params_{}.gz", i));
        let mut file = std::fs::File::create(&chunk_path).expect("Unable to create file");
        file.write_all(chunk).expect("Unable to write data");
    }
}