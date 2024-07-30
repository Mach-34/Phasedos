use crate::mongo::GrapevineDB;
use mongodb::Client;

pub struct GrapevineTestContext {
    client: Client,
}

impl GrapevineTestContext {
    async fn init() -> Self {
        let database_name = String::from("grapevine_mocked");
        let mongo = GrapevineDB::init(&database_name, &*MONGODB_URI).await;
        let rocket = rocket::build()
            // add mongodb client to context
            .manage(mongo)
            // mount user routes
            .mount("/user", &**routes::USER_ROUTES)
            // mount proof routes
            .mount("/proof", &**routes::PROOF_ROUTES)
            // mount test routes
            .mount("/", routes![health])
            // mount artifact file server
            .mount("/static", FileServer::from(relative!("static")))
            .register("/", catchers![bad_request]);

        GrapevineTestContext {
            client: Client::tracked(rocket).await.unwrap(),
        }
    }
}
