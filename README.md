# Grapevine


## Use CLI Live
Built using `rustc 1.82.0-nightly (1f12b9b0f 2024-08-27)`

1. clone the repo
`git clone https://github.com/mach-34/Grapevine && cd Grapevine`

2. install the CLI
`cargo install --path crates/grapevine_cli`

3. use the CLI globally with `grapevine` :)

## Run Local
1. Clone the repo
`git clone https://github.com/mach-34/Grapevine && cd Grapevine`

2. Start the server (in new terminal)
`cd crates/grapevine_server/ && cargo run`

3. Start the database with docker (in new terminal) 
`cd crates/grapevine_server/ && docker compose up`

4. Set the cli env to localhost
`cp crates/grapevine_cli/.example.env crates/grapevine_cli/.env`

Warning: if you've already built the cli for live server interaction, you must run `cargo clean` to re-run the build script that injects the API url.
You must comment out the `.env` file (it will default to https://grapevine.mach34.space live deployment) and run `cargo clean` when switching back as well.

5. Install the grapevine cli (in original terminal window)
`cargo install --path crates/grapevine_cli`

6. Run the basic test demonstrating MVP (or any of the other test scripts)
`./scripts/moving_degree_test.sh`

See [the test file](./scripts/moving_degree_test.sh) for insights on driving the CLI manually.
Docs will come once the codebase is not as messy and edge cases are handled

## Status of JS Library
The JS library functions with proving, allows submission of proofs to the server, and handles communication of secrets used in relationships. However, there are API calls that are not yet implemented, the wasm does not have promises set up (meaning failed proofs will panic), and the library is wildly unorganized (much less ergonomic). These changes will be coming shortly with the integration of Sonobe.