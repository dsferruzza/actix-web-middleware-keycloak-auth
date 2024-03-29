// actix-web-middleware-keycloak-auth
//
// Copyright: 2020, David Sferruzza
// License: MIT

use actix_web::body::BoxBody;
use actix_web::http::StatusCode;
use actix_web::{HttpResponse, ResponseError};

use super::Role;

/// An authentication error
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthError {
    /// The `Authorization` header is missing
    NoAuthorizationHeader,
    /// The value of the `Authorization` header is not `Bearer [JWT]`
    InvalidAuthorizationHeader,
    /// The JWT is invalid (bad structure, wrong signature, ...)
    InvalidJwt(String),
    /// The JWT does not contain expected claims
    DecodeError(String),
    /// The JWT contains role claims that does not have the expected type/structure
    RoleParsingError(String),
    /// The JWT does not contain some required roles
    MissingRoles(Vec<Role>),
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
        HttpResponse::new(self.status_code()).set_body(BoxBody::new(self.to_string()))
    }
}

impl std::fmt::Display for AuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoAuthorizationHeader => f.write_str("No bearer token was provided"),
            Self::InvalidAuthorizationHeader => {
                f.write_str("Authorization header value is invalid (cannot convert it into string)")
            }
            Self::InvalidJwt(e) => write!(f, "Invalid JWT token ({})", e),
            Self::DecodeError(e) => write!(f, "Error while decoding JWT token ({})", e),
            Self::RoleParsingError(e) => write!(
                f,
                "Error while parsing Keycloak roles from JWT token ({})",
                e
            ),
            Self::MissingRoles(roles) => {
                write!(
                    f,
                    "JWT token is missing roles: {}",
                    &roles
                        .iter()
                        .map(|r| r.to_string())
                        .collect::<Vec<String>>()
                        .join(", ")
                )
            }
        }
    }
}

impl AuthError {
    /// Build a HTTP response from an authentication error
    pub fn to_response(&self, detailed_responses: bool) -> HttpResponse {
        if detailed_responses {
            self.error_response()
        } else {
            HttpResponse::build(self.status_code()).body(self.status_code().to_string())
        }
    }
}

/// An error that happened while trying to extract and parse an unstructured claim
#[derive(Debug)]
pub enum ClaimError {
    /// The claim cannot be found
    NotFound(String),
    /// The claim cannot be parsed as the provided/inferred type
    ParseError(String, serde_json::Error),
}

impl std::fmt::Display for ClaimError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotFound(key) => write!(f, "Claim '{}' was not found", key),
            Self::ParseError(key, err) => write!(f, "Parsing claim '{}' failed: {}", key, err),
        }
    }
}
