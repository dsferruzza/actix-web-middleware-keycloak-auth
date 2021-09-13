use actix_web::{FromRequest, ResponseError};
use futures_util::future::{ready, Ready};
use serde::de::DeserializeOwned;
use serde_json::Value;
use std::fmt::Display;
use std::ops::Deref;

use super::RawClaims;

#[derive(Debug, Default)]
pub struct CustomClaimsExtractorConfig;

#[derive(Debug)]
pub struct CustomClaimsExtractorError(serde_json::Error);

impl Display for CustomClaimsExtractorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Error while deserializing JWT: {}", self.0)
    }
}

impl ResponseError for CustomClaimsExtractorError {
    fn status_code(&self) -> actix_web::http::StatusCode {
        actix_web::http::StatusCode::FORBIDDEN
    }
}

/// Extractor for custom JWT claims
#[derive(Debug, Clone)]
pub struct CustomClaims<T: DeserializeOwned>(T);

impl<T: DeserializeOwned> CustomClaims<T> {
    /// Consumes the `CustomClaims`, returning its wrapped data
    pub fn into_inner(self) -> T {
        self.0
    }
}

impl<T: DeserializeOwned> Deref for CustomClaims<T> {
    type Target = T;

    fn deref(&self) -> &T {
        &self.0
    }
}

impl<T: DeserializeOwned> FromRequest for CustomClaims<T> {
    type Config = CustomClaimsExtractorConfig;
    type Error = CustomClaimsExtractorError;
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
                .map_err(CustomClaimsExtractorError),
        )
    }
}
