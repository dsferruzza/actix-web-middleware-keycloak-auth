// actix-web-middleware-keycloak-auth
//
// Copyright: 2020, David Sferruzza
// License: MIT

use actix_web::http::StatusCode;
use actix_web::{HttpResponse, ResponseError};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthError {
    NoBearerToken,
    InvalidAuthorizationHeader,
    InvalidJwt(String),
    DecodeError(String),
    MissingRoles(Vec<String>),
}

impl ResponseError for AuthError {
    fn status_code(&self) -> StatusCode {
        match self {
            Self::MissingRoles(_) => StatusCode::FORBIDDEN,
            Self::InvalidAuthorizationHeader => StatusCode::BAD_REQUEST,
            _ => StatusCode::UNAUTHORIZED,
        }
    }

    fn error_response(&self) -> HttpResponse {
        HttpResponse::build(self.status_code()).body(&self.to_string())
    }
}

impl std::fmt::Display for AuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoBearerToken => f.write_str("No bearer token was provided"),
            Self::InvalidAuthorizationHeader => {
                f.write_str("Authorization header value is invalid (cannot convert it into string)")
            }
            Self::InvalidJwt(e) => write!(f, "Invalid JWT token ({})", e),
            Self::DecodeError(e) => write!(f, "Error while decoding JWT token ({})", e),
            Self::MissingRoles(roles) => {
                write!(f, "JWT token is missing roles: {}", roles.join(", "))
            }
        }
    }
}

impl AuthError {
    pub fn to_response(&self, detailed_responses: bool) -> HttpResponse {
        if detailed_responses {
            self.error_response()
        } else {
            HttpResponse::build(self.status_code()).body(self.status_code().to_string())
        }
    }
}
