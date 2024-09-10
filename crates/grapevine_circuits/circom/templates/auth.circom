pragma circom 2.1.6;

include "../node_modules/circomlib/circuits/poseidon.circom";
include "../node_modules/circomlib/circuits/comparators.circom";
include "../node_modules/circomlib/circuits/eddsaposeidon.circom";


// Computes a bjj address by hashing a pubkey
template BJJAddress() {
    signal input pubkey[2]; // the pubkey to hash into an address
    signal output address; // the computed address

    // hash the pubkey
    component hasher = Poseidon(2);
    hasher.inputs <== pubkey;
    address <== hasher.out;
}

// Constrains the check of a BJJ pubkey to equal a given address
template CheckBJJAddress() {
    signal input pubkey[2];
    signal input address;
    signal input enabled;

    // hash pubkey into address
    component pubkey_to_address = BJJAddress();
    pubkey_to_address.pubkey <== pubkey;

    // check equality if enabled
    component address_equality = ForceEqualIfEnabled();
    address_equality.in[0] <== pubkey_to_address.address;
    address_equality.in[1] <== address;
    address_equality.enabled <== enabled;
    
}

// produces underlying auth message and checks signature over it
template AuthSigVerifier() {
    signal input pubkey[2]; // the pubkey of the signer (previous prover)
    signal input nullifier; // the nullifier issues from prev prover to current prover
    signal input prover; // the current prover's address
    signal input signature[3]; // the signature over auth message by pubkey ([R8.x, R8.y, s])
    signal input enabled; // whether or not to enforce the constraint

    // compute the auth message
    component auth_message = Poseidon(2);
    auth_message.inputs[0] <== nullifier;
    auth_message.inputs[1] <== prover;

    // verify the signature over the auth message
    component sig_verifier = EdDSAPoseidonVerifier();
    sig_verifier.Ax <== pubkey[0];
    sig_verifier.Ay <== pubkey[1];
    sig_verifier.M <== auth_message.out;
    sig_verifier.R8x <== signature[0];
    sig_verifier.R8y <== signature[1];
    sig_verifier.S <== signature[2];
    sig_verifier.enabled <== enabled;
}

// checks the authenticity of a given scope signature (sig by current prover over scope address)
// a bit redundant but makes grapevine circuit more readable
template ScopeSigVerifier() {
    signal input pubkey[2];
    signal input scope;
    signal input signature[3];
    signal input enabled;

    // verify the signature over the auth message
    component sig_verifier = EdDSAPoseidonVerifier();
    sig_verifier.Ax <== pubkey[0];
    sig_verifier.Ay <== pubkey[1];
    sig_verifier.M <== scope;
    sig_verifier.R8x <== signature[0];
    sig_verifier.R8y <== signature[1];
    sig_verifier.S <== signature[2];
    sig_verifier.enabled <== enabled;
}