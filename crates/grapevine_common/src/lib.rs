use nova_scotia::{circom::circuit::CircomCircuit, C1, C2, F};
use nova_snark::{provider, traits::circuit::TrivialTestCircuit, PublicParams, RecursiveSNARK};

pub mod account;
pub mod auth_secret;
pub mod compat;
pub mod crypto;
pub mod errors;
pub mod http;
pub mod models;
pub mod utils;

pub type G1 = provider::bn256_grumpkin::bn256::Point;
pub type G2 = provider::bn256_grumpkin::grumpkin::Point;
pub type Fr = F<G1>;
pub type Fq = F<G2>;
pub type Params = PublicParams<G1, G2, C1<G1>, C2<G2>>;
pub type NovaProof = RecursiveSNARK<G1, G2, CircomCircuit<Fr>, TrivialTestCircuit<Fq>>;

pub const SECRET_FIELD_LENGTH: usize = 6;
pub const MAX_SECRET_CHARS: usize = 180;
pub const MAX_USERNAME_CHARS: usize = 30;
