use clap::{Parser, Subcommand};
mod controllers;
mod http;
mod test;
mod utils;

///    ______                           _
///   / ____/________ _____  ___ _   __(_)___  ___
///  / / __/ ___/ __ `/ __ \/ _ \ | / / / __ \/ _ \
/// / /_/ / /  / /_/ / /_/ /  __/ |/ / / / / /  __/
/// \____/_/   \__,_/ .___/\___/|___/_/_/ /_/\___/
///                /_/
///
#[derive(Parser)]
#[command(author, version, about, long_about = None, verbatim_doc_comment)]
#[command(propagate_version = true)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
#[command(verbatim_doc_comment)]
enum Commands {
    /// Test the connection to the Grapevine server
    /// usage: `grapevine health`
    #[command(verbatim_doc_comment)]
    Health,
    /// Commands for managing your Grapevine account
    #[command(subcommand, verbatim_doc_comment)]
    Account(AccountCommands),
    /// Commands for managing relationships
    #[command(subcommand, verbatim_doc_comment)]
    Relationship(RelationshipCommands),
    /// Commands for interacting with identity and degree proofs
    #[command(subcommand, verbatim_doc_comment)]
    Proof(ProofCommands),
}

#[derive(Subcommand)]
enum RelationshipCommands {
    /// Send a new relationship request or accept a pending request
    /// usage: `grapevine relationship add <username>`
    #[command(verbatim_doc_comment)]
    #[clap(value_parser)]
    Add { username: String },
    /// Show pending relationship requests from other users
    /// usage: `grapevine relationship pending`
    #[command(verbatim_doc_comment)]
    Pending,
    /// Reject a pending relationship request
    /// usage: `grapevine relationship reject <username>`
    #[command(verbatim_doc_comment)]
    #[clap(value_parser)]
    Reject { username: String },
    /// Remove a relationship by username
    /// usage: `grapevine relationship remove <username>`
    #[command(verbatim_doc_comment)]
    #[clap(value_parser)]
    Remove { username: String },
    /// List the usernames of all of your active relationships
    /// usage: `grapevine relationship list`
    #[command(verbatim_doc_comment)]
    List,

    /// List the usernames of counterparties that have nullified their relationship with you
    /// usage: `grapevine relationship reveal-nullified`
    #[command(verbatim_doc_comment)]
    RevealNullified,
}

#[derive(Subcommand)]
enum AccountCommands {
    /// Register a new Grapevine account
    /// usage: `grapevine account register <username>`
    #[command(verbatim_doc_comment)]
    #[clap(value_parser)]
    Register { username: String },
    /// Get information about your Grapevine account
    /// usage: `grapevine account info`
    #[command(verbatim_doc_comment)]
    Info,
    /// Export the Baby JubJub private key for your account
    /// usage: `grapevine account export`
    #[command(verbatim_doc_comment)]
    Export,
}

#[derive(Subcommand)]
enum ProofCommands {
    /// Retrieve a list of available degree proofs to build from
    /// usage: `grapevine proof available
    #[command(verbatim_doc_comment)]
    Available,
    /// List all your degree proofs
    /// usage: `grapevine proof list`
    #[command(verbatim_doc_comment)]
    List,
    /// Prove all available degrees
    /// usage: `grapevine proof sync
    #[command(verbatim_doc_comment)]
    Sync,
    /// Get your degree proof for a given scope
    /// usage: `grapevine proof scope <username>
    #[command(verbatim_doc_comment)]
    #[clap(value_parser)]
    Scope { username: String },
}

/**
 * CLI for Grapevine
 */
#[tokio::main]
pub async fn main() {
    let cli = Cli::parse();

    let result = match &cli.command {
        Commands::Account(cmd) => match cmd {
            AccountCommands::Register { username } => controllers::register(username).await,
            AccountCommands::Info => controllers::account_details().await,
            AccountCommands::Export => controllers::export_key(),
        },
        Commands::Health => controllers::health().await,
        Commands::Proof(cmd) => match cmd {
            ProofCommands::Available => controllers::get_available_proofs().await,
            ProofCommands::List => controllers::get_my_proofs().await,
            ProofCommands::Sync => controllers::prove_all_available().await,
            ProofCommands::Scope { username } => {
                controllers::get_proof_metadata_by_scope(username).await
            }
        },
        Commands::Relationship(cmd) => match cmd {
            RelationshipCommands::Add { username } => controllers::add_relationship(username).await,
            RelationshipCommands::Pending => controllers::get_relationships(false).await,
            RelationshipCommands::Reject { username } => {
                controllers::reject_relationship(username).await
            }
            RelationshipCommands::Remove { username } => {
                controllers::nullify_relationship(username).await
            }
            RelationshipCommands::List => controllers::get_relationships(true).await,
            RelationshipCommands::RevealNullified => {
                controllers::list_relationships_to_nullify().await
            }
        },
    };

    match result {
        Ok(message) => {
            println!("{}", message);
        }
        Err(e) => {
            println!("Error: {}", e);
        }
    };
}
