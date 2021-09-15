use actix_web::{FromRequest, ResponseError};
use futures_util::future::{ready, Ready};
use serde::de::DeserializeOwned;
use serde_json::Value;
use std::fmt::Display;
use std::ops::Deref;

use super::RawClaims;

#[derive(Debug, Default)]
pub struct KeycloakClaimsExtractorConfig;

#[derive(Debug)]
pub struct KeycloakClaimsExtractorError(serde_json::Error);

impl Display for KeycloakClaimsExtractorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Error while deserializing JWT: {}", self.0)
    }
}

impl ResponseError for KeycloakClaimsExtractorError {
    fn status_code(&self) -> actix_web::http::StatusCode {
        actix_web::http::StatusCode::FORBIDDEN
    }
}

/// Actix-web extractor for custom JWT claims
#[derive(Debug, Clone)]
pub struct KeycloakClaims<T: DeserializeOwned>(T);

impl<T: DeserializeOwned> KeycloakClaims<T> {
    /// Consumes the `KeycloakClaims`, returning its wrapped data
    pub fn into_inner(self) -> T {
        self.0
    }
}

impl<T: DeserializeOwned> Deref for KeycloakClaims<T> {
    type Target = T;

    fn deref(&self) -> &T {
        &self.0
    }
}

impl<T: DeserializeOwned> FromRequest for KeycloakClaims<T> {
    type Config = KeycloakClaimsExtractorConfig;
    type Error = KeycloakClaimsExtractorError;
    type Future = Ready<Result<Self, Self::Error>>;

    fn from_request(
        req: &actix_web::HttpRequest,
        _payload: &mut actix_web::dev::Payload,
    ) -> Self::Future {
        let extensions = req.extensions();
        let raw_claims = extensions
            .get::<RawClaims>()
            .unwrap_or(&RawClaims(Value::Null));
        let deserialized_claims = serde_json::from_value::<T>(raw_claims.0.to_owned());
        ready(
            deserialized_claims
                .map(Self)
                .map_err(KeycloakClaimsExtractorError),
        )
    }
}
