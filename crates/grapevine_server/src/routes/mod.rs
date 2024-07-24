use lazy_static::lazy_static;
use rocket::route::Route;
mod proof;
mod user;

lazy_static! {
    pub(crate) static ref USER_ROUTES: Vec<Route> = routes![
        user::add_relationship,
        user::get_nullifier_secret,
        user::get_relationship,
        user::emit_nullifier,
        // user::reject_pending_relationship,
        // user::get_pending_relationships,
        // user::get_active_relationships,
        // user::get_account_details,
        // user::get_user,
        // user::get_nonce,
        // user::get_pubkey,
        // user::get_all_degrees
    ];
    pub(crate) static ref PROOF_ROUTES: Vec<Route> = routes![
        proof::prove_identity,
        proof::degree_proof,
        proof::get_available_proofs,
        proof::get_proof_with_params,
        proof::get_proof_by_scope
    ];
}
