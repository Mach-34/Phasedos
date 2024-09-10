pragma circom 2.1.6;

include "../node_modules/circomlib/circuits/mux1.circom";
include "../node_modules/circomlib/circuits/comparators.circom";

// Returns booleans for whether the step is identity, or degree step
// Uses scope != 0 since it will only be 0 for first ivc step
// Will return 0 for both if obfuscation step
template StepType() {
    signal input obfuscate;
    signal input scope;

    signal output identity;
    signal output degree;

    // check if scope is 0
    component scope_is_zero = IsZero();
    scope_is_zero.in <== scope;

    component step_mux = MultiMux1(2);
    step_mux.s <== scope_is_zero.out;
    // @ NOTE NEVER CHAFF IF IDENTITY IS TRUE FIX
    // if scope is 0 (true), then this is an identity step
    step_mux.c[0][0] <== 0;
    step_mux.c[0][1] <== 1 - obfuscate;
    // if scope is not 0 (false), then this is a degree step
    step_mux.c[1][0] <== 1 - obfuscate;
    step_mux.c[1][1] <== 0;

    identity <== step_mux.out[0];
    degree <== step_mux.out[1];
}

// Parses the input step_in into labeled signals & validates them
// Checks that obfuscation flag == 0 or 1
// Checks whether the degree has exceeded provable limit (array length limits nullifiers to 8)
// If step 1, also enforces all inputs === 0
// Additionally provides booleans for step type
template ParseInputs() {

    /// STEP IO SCHEMA ///
    // 0: obfuscation flag
    // 1: degrees of separation
    // 2: scope address (identity proof creator/ degree 0)
    // 3: previous proof creator address
    // 4-11: nullifiers
    signal input step_in[12];
    
    signal output obfuscate; // boolean flag to determine if this is an obfuscation step
    signal output degree; // the degree of separation from relation to scope
    signal output scope; // the address of the prover of the identity proof
    signal output relation; // the address of the prover of the previous (degree) proof
    signal output nullifiers[8]; // array of nullifiers for each degree
    signal output is_identity_step; // boolean denoting if step is identity (0 if obfuscated)
    signal output is_degree_step; // boolean denoting if step is degree (0 if obfuscated)

    // label inputs
    obfuscate <== step_in[0];
    degree <== step_in[1];
    scope <== step_in[2];
    relation <== step_in[3];
    for (var i = 0; i < 8; i++) {
        nullifiers[i] <== step_in[4 + i];
    }

    // Check obfuscation flag is binary
    obfuscate * (obfuscate - 1) === 0;

    // Determine what type of step the proof is on
    component step_type = StepType();
    step_type.obfuscate <== obfuscate;
    step_type.scope <== scope;
    is_identity_step <== step_type.identity;
    is_degree_step <== step_type.degree;

    // **Only constrained if IDENTITY step**
    // Check every input for identity proof (step 0) === 0
    component zero_check[12];
    for (var i = 0; i < 12; i++) {
        zero_check[i] = ForceEqualIfEnabled();
        zero_check[i].in[0] <== step_in[i];
        zero_check[i].in[1] <== 0;
        zero_check[i].enabled <== is_identity_step;
    }

    // **Only constrained if DEGREE step** 
    // Don't need to check on identity step since will always === 0
    // Check degree is < 8
    component lt_eq_8 = LessEqThan(4);
    lt_eq_8.in[0] <== degree;
    lt_eq_8.in[1] <== 8;

    component degree_boundary = ForceEqualIfEnabled();
    degree_boundary.in[0] <== lt_eq_8.out;
    degree_boundary.in[1] <== 1;
    degree_boundary.enabled <== is_degree_step;
}

// Insers nullifier indexed by degree if current step is a degree step
template NullifierAssignment() {
    signal input in[8]; // the nullifiers given from IVC step input
    signal input degree; // the degree of relation from scope given from IVC step input
    signal input relation_nullifier; // the nullifier issued by relation to prover
    signal input enabled; // toggle to not mutate nullifiers if not degree step
    signal output out[8]; // nullifiers after (maybe) appending relation_nullifier 

    // iterate through each nullifier index to assign the right one
    component index_eq[8];
    component assign_mux[8];

    for (var i = 0; i < 8; i++) {
        // check if this is the index to increment
        index_eq[i] = IsEqual();
        index_eq[i].in[0] <== degree;
        index_eq[i].in[1] <== i;


        // mux through the previous nullifier if 0 or the new one if 1
        assign_mux[i] = Mux1();
        assign_mux[i].s <== index_eq[i].out * enabled;
        assign_mux[i].c[0] <== in[i];
        assign_mux[i].c[1] <== relation_nullifier;

        // set the output
        out[i] <== assign_mux[i].out;
    }
}

// Handles assignment of step_out according to step type (and degree index for nullifier)
template MarshalOutputs() {
    signal input obfuscate; // the obfuscation flag passed from step_in[0]
    signal input degree; // the degree flag passed from step_in[1]
    signal input scope; // the scope address passed from step_in[2]
    signal input relation; // the relation address passed from step_in[3]
    signal input nullifiers[8]; // the nullifiers passed from step_in[4-11]
    signal input prover; // the address computed from prover pubkey (IDENTITY)
    signal input relation_nullifier; // the nullifier issued by the relation to prover (DEGREE)
    signal input identity_step; // boolean flag denoting if this is an identity step
    signal input degree_step; // boolean flag denoting if this is a degree step

    signal output step_out[12]; // the output array to be passed to the next step

    // toggle the obfuscate flag
    step_out[0] <== 1 - obfuscate; // safe since obfuscate is constrained binary in ParseInputs

    // increment degree if not obfuscation or identity step
    step_out[1] <== degree + degree_step; // degree_step = 0 if obfuscate or identity step

    // Set the scope address as computed in the proof if identity step
    // Otherwise set scope output from input
    component scope_mux = Mux1();
    scope_mux.s <== identity_step;
    scope_mux.c[0] <== scope;
    scope_mux.c[1] <== prover;
    step_out[2] <== scope_mux.out;

    // Set the relation address as computed in the proof if identity or degree step
    // Otherwise when obfuscation step set relation output from input
    component relation_mux = Mux1();
    relation_mux.s <== obfuscate;
    relation_mux.c[0] <== prover;
    relation_mux.c[1] <== relation;
    step_out[3] <== relation_mux.out;

    // Assign next nullifier according to degree indexing if degree step
    // Otherwise pass through the nullifiers from the input
    component nullifier_assignment = NullifierAssignment();
    nullifier_assignment.in <== nullifiers;
    nullifier_assignment.degree <== degree;
    nullifier_assignment.relation_nullifier <== relation_nullifier;
    nullifier_assignment.enabled <== degree_step;

    for (var i = 0; i < 8; i++) {
        step_out[4 + i] <== nullifier_assignment.out[i];
    }
}