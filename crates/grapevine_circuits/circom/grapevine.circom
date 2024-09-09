pragma circom 2.1.6;

include "./node_modules/circomlib/circuits/mux1.circom";
include "./templates/auth.circom";
include "./templates/step_utils.circom";

template Grapevine() { 

   signal input relation_pubkey[2]; // the pubkey of the previous prover
   signal input prover_pubkey[2]; // the pubkey of current prover showing connection to relation
   signal input relation_nullifier; // the nullifier issued by the previous prover
   signal input auth_signature[3]; // the signature by relation over H|nullifier, prover address|
   signal input scope_signature[3]; // the signature by prover over scope address

   // See ./templates/step_utils.circom:ParseInputs for deserialization schema
   signal input step_in[12];
   signal output step_out[12];

   // Parse step inputs into labeled signals & validate them
   component inputs = ParseInputs();
   inputs.step_in <== step_in;

   // **Only constrained if DEGREE step**
   // Check the relation pubkey hashes to the relation address
   component validate_relation_pubkey = CheckBJJAddress();
   log("relation_pubkey x", relation_pubkey[0]);
   log("relation_pubkey y", relation_pubkey[1]);
   log("prover_pubkey x", prover_pubkey[0]);
   log("prover_pubkey y", prover_pubkey[1]);
   log("scope ", inputs.scope);
   log("relation ", inputs.relation);
   log("relation_nullifier ", relation_nullifier);
   validate_relation_pubkey.pubkey <== relation_pubkey;
   validate_relation_pubkey.address <== inputs.relation;
   validate_relation_pubkey.enabled <== inputs.is_degree_step;

   // Compute the current prover's address
   component prover = BJJAddress();
   prover.pubkey <== prover_pubkey;
   log("prover address", prover.address);

   // Multiplex between identity and degree steps to get scope
   // If chaff step, verifier will be disabled so incorrect assignment is ok
   component identity_scope_mux = Mux1();
   identity_scope_mux.s <== inputs.is_degree_step;
   identity_scope_mux.c[0] <== prover.address;
   identity_scope_mux.c[1] <== inputs.scope;

   // **Only constrained if IDENTITY or DEGREE step**
   // Verify prover address controls the used pubkey with scope address
   component identity_verifier = ScopeSigVerifier();
   identity_verifier.pubkey <== prover_pubkey;
   identity_verifier.scope <== identity_scope_mux.out;
   identity_verifier.signature <== scope_signature;
   identity_verifier.enabled <== 1 - inputs.obfuscate;

   // **Only constrained if DEGREE step**
   // Verify the prover has a connection to relation by verifying the auth signature
   // Also validates the authenticity of the issued nullifier
   component auth_verifier = AuthSigVerifier();
   auth_verifier.pubkey <== relation_pubkey;
   auth_verifier.nullifier <== relation_nullifier;
   auth_verifier.prover <== prover.address;
   auth_verifier.signature <== auth_signature;
   auth_verifier.enabled <== inputs.is_degree_step;

   // Marshal outputs into step out conditional to step type
   component marshal_outputs = MarshalOutputs();
   marshal_outputs.obfuscate <== inputs.obfuscate;
   marshal_outputs.degree <== inputs.degree;
   marshal_outputs.scope <== inputs.scope;
   marshal_outputs.relation <== inputs.relation;
   marshal_outputs.nullifiers <== inputs.nullifiers;
   marshal_outputs.prover <== prover.address;
   marshal_outputs.relation_nullifier <== relation_nullifier;
   marshal_outputs.identity_step <== inputs.is_identity_step;
   marshal_outputs.degree_step <== inputs.is_degree_step;

   // Assign output signals
   step_out <== marshal_outputs.step_out;
}


component main { public [step_in] } = Grapevine();