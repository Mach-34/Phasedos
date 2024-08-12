use crate::{
    mongo::GrapevineDB,
    routes::PROOF_ROUTES,
    tests::helpers::{parse_path_segments, GrapevineTestContext},
};
use grapevine_common::errors::GrapevineError;
use lazy_static::lazy_static;
use rocket::{http::Method, local::asynchronous::LocalResponse, Route};

#[cfg(test)]
mod auth_guard_tests {
    use grapevine_common::account::GrapevineAccount;
    use rocket::http::Header;

    use crate::tests::{
        helpers::{build_create_user_request, generate_nonce_signature},
        http::http_create_user,
    };

    use super::*;

    #[rocket::async_test]
    async fn test_missing_username_header() {
        let context = GrapevineTestContext::init().await;
        GrapevineDB::drop("grapevine_mocked").await;

        let url = "/user/details";
        let res = context.client.get(url).dispatch().await;
        assert_eq!(res.status().code, 400);

        let missing_username_header =
            GrapevineError::HeaderError(String::from("couldn't find X-Username"));

        let msg = res.into_json::<GrapevineError>().await.unwrap();
        assert_eq!(missing_username_header.to_string(), msg.to_string());
    }

    #[rocket::async_test]
    async fn test_missing_nonce_signature_header() {
        let context = GrapevineTestContext::init().await;
        GrapevineDB::drop("grapevine_mocked").await;

        let username = String::from("username");

        let url = "/user/details";
        let res = context
            .client
            .get(url)
            .header(Header::new("X-Username", username))
            .dispatch()
            .await;
        assert_eq!(res.status().code, 400);

        let missing_signature_header =
            GrapevineError::HeaderError(String::from("couldn't find X-Authorization"));

        let msg = res.into_json::<GrapevineError>().await.unwrap();
        assert_eq!(missing_signature_header.to_string(), msg.to_string());
    }

    #[rocket::async_test]
    async fn test_invalid_hex_string_signature_header() {
        let context = GrapevineTestContext::init().await;
        GrapevineDB::drop("grapevine_mocked").await;

        let user = GrapevineAccount::new(String::from("username"));
        let username = user.username().clone();
        let signature = generate_nonce_signature(&user);

        let url = "/user/details";
        let res = context
            .client
            .get(url)
            .header(Header::new(
                "X-Authorization",
                String::from(&signature[2..]),
            ))
            .header(Header::new("X-Username", username))
            .dispatch()
            .await;
        assert_eq!(res.status().code, 400);

        let invalid_hex_header = GrapevineError::HeaderError(String::from(
            "invalid hex string provided for X-Authorization header",
        ));

        let msg = res.into_json::<GrapevineError>().await.unwrap();
        assert_eq!(invalid_hex_header.to_string(), msg.to_string());
    }

    #[rocket::async_test]
    async fn test_invalid_nonce_signature_header() {
        let context = GrapevineTestContext::init().await;
        GrapevineDB::drop("grapevine_mocked").await;

        let user = GrapevineAccount::new(String::from("username"));
        let username = user.username().clone();
        let fake_signature = hex::encode("f".repeat(64));

        let url = "/user/details";
        let res = context
            .client
            .get(url)
            .header(Header::new("X-Authorization", fake_signature))
            .header(Header::new("X-Username", username))
            .dispatch()
            .await;
        assert_eq!(res.status().code, 400);

        let malformed_signature_header =
            GrapevineError::HeaderError(String::from("couldn't parse X-Authorization"));

        let msg = res.into_json::<GrapevineError>().await.unwrap();
        assert_eq!(malformed_signature_header.to_string(), msg.to_string());
    }

    #[rocket::async_test]
    async fn test_non_existent_user() {
        let context = GrapevineTestContext::init().await;
        GrapevineDB::drop("grapevine_mocked").await;

        let user = GrapevineAccount::new(String::from("username"));

        let username = user.username().clone();
        let signature = generate_nonce_signature(&user);

        let url = "/user/details";
        let res = context
            .client
            .get(url)
            .header(Header::new("X-Authorization", signature))
            .header(Header::new("X-Username", username.clone()))
            .dispatch()
            .await;
        assert_eq!(res.status().code, 404);

        let expected_msg = format!("Username {} does not exist", username);

        let msg = res.into_string().await.unwrap();
        assert_eq!(expected_msg, msg);
    }

    #[rocket::async_test]
    async fn test_incorrect_nonce_signed() {
        let context = GrapevineTestContext::init().await;
        GrapevineDB::drop("grapevine_mocked").await;

        let mut user = GrapevineAccount::new(String::from("username"));

        // increment nonce twice prematurely
        _ = user.increment_nonce(None);
        _ = user.increment_nonce(None);

        let username = user.username().clone();
        let signature = generate_nonce_signature(&user);

        // create user
        let request = build_create_user_request(&user);
        http_create_user(&context, &request).await;

        let url = "/user/details";
        let res = context
            .client
            .get(url)
            .header(Header::new("X-Authorization", signature))
            .header(Header::new("X-Username", username.clone()))
            .dispatch()
            .await;

        assert_eq!(res.status().code, 401);

        let nonce_verification_error =
            GrapevineError::Signature(String::from("Failed to verify nonce signature"));
        let msg = res.into_json::<GrapevineError>().await.unwrap();
        assert_eq!(nonce_verification_error.to_string(), msg.to_string());
    }
}

/*
    Tests to ensure all routes that require authorization are all properly authed. Should include:

    === Proof routes ===
    * POST /proof/degree (degree_proof)
    * GET /proof/available (get_available_proofs)
    * GET /proof/proven (get_proven_degrees)
    * GET /proof/scope/<scope> (get_proof_by_scope)
    * GET /proof/metadata/<scope> (get_proof_metadata_by_scope)
    * GET /proof/params/<oid> (get_proof_with_params)

    === User routes ===
    * POST /user/relationship/add (add_relatioship)
    * GET /user/<recipient>/nullifier-secret (get_nullifier_secret)
    * POST /user/relationship/nullify (emit_nullifier)
    * POST /user/relationship/reject/<username> (reject_pending_relationship)
    * GET /user/relationship/pending (get_pending_relationship)
    * GET /user/relationship/active (get_active_relationship)
    * GET /user/details (get_account_details)
*/

lazy_static! {
    static ref AUTHED_PROOF_ROUTES: Vec<String> = vec![
        String::from("degree_proof"),
        String::from("get_available_proofs"),
        String::from("get_proven_degrees"),
        String::from("get_proof_by_scope"),
        String::from("get_proof_metadata_by_scope"),
        String::from("get_proof_with_params"),
    ];
    static ref AUTHED_USER_ROUTES: Vec<String> = vec![
        String::from("add_relationship"),
        String::from("get_nullifier_secret"),
        String::from("emit_nullifier"),
        String::from("reject_pending_relationship"),
        String::from("get_pending_relationship"),
        String::from("get_active_relationship"),
        String::from("get_account_details")
    ];
}

#[cfg(test)]
mod route_auth_tests {
    use crate::routes::USER_ROUTES;

    use super::*;

    #[rocket::async_test]
    async fn test_auth_guard() {
        let context = GrapevineTestContext::init().await;
        GrapevineDB::drop("grapevine_mocked").await;

        let routes = [&PROOF_ROUTES[..], &USER_ROUTES[..]].concat();

        let authed_routes = routes
            .iter()
            .filter_map(|route| {
                let route_name = &route.name.clone().unwrap().to_string();
                let is_authed_proof_route = AUTHED_PROOF_ROUTES.contains(route_name);
                let is_authed_user_route = AUTHED_USER_ROUTES.contains(route_name);

                if is_authed_proof_route {
                    Some((route, "proof"))
                } else if is_authed_user_route {
                    Some((route, "user"))
                } else {
                    None
                }
            })
            .collect::<Vec<(&Route, &str)>>();

        // response errors to expect
        let missing_username_header =
            GrapevineError::HeaderError(String::from("couldn't find X-Username"));

        // test proof routes
        for (route, prefix) in authed_routes {
            // handle segments
            let path = parse_path_segments(&route);
            let url = format!("/{}/{}", prefix, path);
            let mut res_option: Option<LocalResponse> = None;
            if route.method == Method::Get {
                res_option = Some(context.client.get(url).dispatch().await)
            } else {
                res_option = Some(context.client.post(url).dispatch().await);
            }
            let res = res_option.unwrap();
            assert_eq!(res.status().code, 400); // assert unauthorized error code has been returned
            let msg = res.into_json::<GrapevineError>().await.unwrap();
            assert_eq!(missing_username_header.to_string(), msg.to_string());
        }
    }
}
