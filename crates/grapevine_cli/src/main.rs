use clap::{Parser, Subcommand};
mod controllers;
mod http;
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
    // /// Commands for interacting with phrases and degree proofs
    // #[command(subcommand, verbatim_doc_comment)]
    // Phrase(PhraseCommands),
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
    /// List the username of all of your active relationships
    /// usage: `grapevine relationship list`
    #[command(verbatim_doc_comment)]
    List,
}

#[derive(Subcommand)]
enum AccountCommands {
    /// Register a new Grapevine account
    /// usage: `grapevine account register <username>`
    #[command(verbatim_doc_comment)]
    Register {
        #[clap(value_parser)]
        username: String,
    },
    /// Get information about your Grapevine account
    /// usage: `grapevine account info`
    #[command(verbatim_doc_comment)]
    Info,
    /// Export the Baby JubJub private key for your account
    /// usage: `grapevine account export`
    #[command(verbatim_doc_comment)]
    Export,
}

// #[derive(Subcommand)]
// enum PhraseCommands {
//     /// Prove knowledge of a phrase. Description is discarded if the phrase already exists
//     /// usage: `grapevine phrase prove "<phrase>" "<description>"`
//     #[command(verbatim_doc_comment)]
//     #[clap(value_parser)]
//     Prove { phrase: String, description: String },
//     /// Check for new degree proofs from relationships and build degrees on top of them
//     /// usage: `grapevine phrase sync`
//     #[command(verbatim_doc_comment)]
//     Sync,
//     /// Get all information known by this account about a given phrase by its index
//     /// usage: `grapevine phrase get <index>`
//     #[command(verbatim_doc_comment)]
//     #[clap(value_parser)]
//     Get { index: u32 },
//     /// Return all phrases known by this account (degree 1)
//     /// usage: `grapevine phrase known`
//     #[command(verbatim_doc_comment)]
//     Known,
//     /// Return all degree proofs created by this account (degree > 1)
//     /// usage: `grapevine phrase degrees`
//     #[command(verbatim_doc_comment)]
//     Degrees,
// }

/**
 * CLI for Grapevine
 */
#[tokio::main]
pub async fn main() {
    let cli = Cli::parse();

    let result = match &cli.command {
        Commands::Health => controllers::health().await,
        Commands::Account(cmd) => match cmd {
            AccountCommands::Register { username } => controllers::register(username).await,
            AccountCommands::Info => controllers::account_details().await,
            AccountCommands::Export => controllers::export_key(),
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
        },
        //     Commands::Phrase(cmd) => match cmd {
        //         PhraseCommands::Prove {
        //             phrase,
        //             description,
        //         } => controllers::prove_phrase(phrase, description).await,
        //         PhraseCommands::Sync => controllers::prove_all_available().await,
        //         PhraseCommands::Get { index } => controllers::get_phrase(*index).await,
        //         PhraseCommands::Known => controllers::get_known_phrases().await,
        //         PhraseCommands::Degrees => controllers::get_my_proofs().await,
        //     },
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
