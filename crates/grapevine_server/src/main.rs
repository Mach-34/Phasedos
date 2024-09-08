#[macro_use]
extern crate rocket;
use catchers::{bad_request, not_found, unauthorized};
use lazy_static::lazy_static;
use mongo::GrapevineDB;
use mongodb::bson::doc;
use rocket::fs::{relative, FileServer};

mod catchers;
mod guards;
mod mongo;
mod routes;
mod utils;

#[cfg(test)]
mod tests {
    mod auth;
    mod helpers;
    mod http;
    mod proof;
    mod user;
}

lazy_static! {
    static ref MONGODB_URI: String = String::from(env!("MONGODB_URI"));
    static ref DATABASE_NAME: String = String::from(env!("DATABASE_NAME"));
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // connect to mongodb
    let mongo = GrapevineDB::init(&*&DATABASE_NAME, &*&MONGODB_URI).await;
    // Initialize logger
    tracing_subscriber::fmt::init();
    // TODO: Route formatting/ segmenting logic
    let mut server = rocket::build()
        // add mongodb client to context
        .manage(mongo)
        // mount user routes
        .mount("/user", &**routes::USER_ROUTES)
        // mount proof routes
        .mount("/proof", &**routes::PROOF_ROUTES)
        // mount artifact file server
        .mount("/static", FileServer::from(relative!("static")))
        // mount test methods (TO BE REMOVED)
        .mount("/test", routes![health])
        // register request guards
        .register("/", catchers![bad_request, not_found, unauthorized]);

    // mount dev routes if not run in release
    #[cfg(debug_assertions)]
    {
        server = server.mount("/dev", routes![reset_db]);
    }

    server.launch().await?;
    Ok(())
}

#[get("/health")]
pub async fn health() -> &'static str {
    "Hello, world!"
}

#[cfg(debug_assertions)]
#[delete("/reset-db")]
pub async fn reset_db() {
    GrapevineDB::drop("grapevine").await;
}
