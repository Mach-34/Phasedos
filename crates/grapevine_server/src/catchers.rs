use grapevine_common::errors::GrapevineError;
use rocket::{
    http::{ContentType, Status},
    request::Request,
    response::{self, Responder, Response},
    serde::json::Json,
};
use serde::{Deserialize, Serialize};

// TODO: Rename to GrapvineServerError?

#[derive(Responder)]
pub enum GrapevineResponse {
    #[response(status = 200)]
    Ok(String),
    #[response(status = 201)]
    Created(String),
    #[response(status = 400)]
    BadRequest(ErrorMessage),
    #[response(status = 401)]
    Unauthorized(ErrorMessage),
    #[response(status = 404)]
    NotFound(String),
    #[response(status = 409)]
    Conflict(ErrorMessage),
    #[response(status = 413)]
    TooLarge(String),
    #[response(status = 500)]
    InternalError(ErrorMessage),
    // #[response(status = 501)]
    // NotImplemented(String),
}

#[catch(400)]
pub fn bad_request(req: &Request) -> GrapevineResponse {
    let res = req.local_cache(|| ErrorMessage(None));
    GrapevineResponse::BadRequest(ErrorMessage(res.0.clone()))
}

#[catch(401)]
pub fn unauthorized(req: &Request) -> GrapevineResponse {
    let res = req.local_cache(|| ErrorMessage(None));
    GrapevineResponse::Unauthorized(ErrorMessage(res.0.clone()))
}

#[catch(404)]
pub fn not_found(req: &Request) -> GrapevineResponse {
    let res = req.local_cache(|| ErrorMessage(None));
    // TODO:  Figure out whether to get rid of error message enum or put not
    //        found response inside
    GrapevineResponse::NotFound(res.0.clone().unwrap().to_string())
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ErrorMessage(pub Option<GrapevineError>);

impl<'r> Responder<'r, 'static> for ErrorMessage {
    fn respond_to(self, req: &'r Request<'_>) -> response::Result<'static> {
        let body = match self.0.is_some() {
            true => Json(self.0.unwrap()),
            false => Json(GrapevineError::InternalError),
        };
        let mut res = Response::build_from(body.respond_to(req)?);

        res.header(ContentType::JSON).ok()
    }
}
