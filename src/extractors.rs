// actix-web-middleware-keycloak-auth
//
// Copyright: 2020, David Sferruzza
// License: MIT

use actix_web::{FromRequest, ResponseError};
use futures_util::future::{ready, Ready};
use serde::de::DeserializeOwned;
use std::fmt::Display;
use std::ops::Deref;

use super::{RawClaims, Role, StandardClaims, UnstructuredClaims};

#[derive(Debug)]
pub enum KeycloakExtractorError {
    ClaimsExtraction,
    Claims(serde_json::Error),
    RolesExtraction,
}

impl Display for KeycloakExtractorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ClaimsExtraction => write!(f, "Could not find JWT claims in ReqData"),
            Self::Claims(e) => write!(f, "Error while deserializing JWT: {}", e),
            Self::RolesExtraction => write!(f, "Could not find Keycloak roles in ReqData"),
        }
    }
}

impl ResponseError for KeycloakExtractorError {
    fn status_code(&self) -> actix_web::http::StatusCode {
        match self {
            Self::ClaimsExtraction => actix_web::http::StatusCode::FORBIDDEN,
            Self::Claims(_) => actix_web::http::StatusCode::FORBIDDEN,
            Self::RolesExtraction => actix_web::http::StatusCode::FORBIDDEN,
        }
    }
}

/// Actix Web extractor for custom JWT claims
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

/// Extract custom JWT claims from an Actix Web request
pub fn extract_jwt_claims<T: DeserializeOwned>(
    req: &actix_web::HttpRequest,
) -> Result<T, KeycloakExtractorError> {
    let extensions = req.extensions();
    match extensions.get::<RawClaims>() {
        Some(raw_claims) => {
            let deserialized_claims = serde_json::from_value::<T>(raw_claims.0.to_owned());

            deserialized_claims.map_err(KeycloakExtractorError::Claims)
        }
        None => Err(KeycloakExtractorError::ClaimsExtraction),
    }
}

impl<T: DeserializeOwned> FromRequest for KeycloakClaims<T> {
    type Error = KeycloakExtractorError;
    type Future = Ready<Result<Self, Self::Error>>;

    fn from_request(
        req: &actix_web::HttpRequest,
        _payload: &mut actix_web::dev::Payload,
    ) -> Self::Future {
        ready(extract_jwt_claims(req).map(Self))
    }
}

/// Actix Web extractor for unstructured JWT claims (see [UnstructuredClaims](UnstructuredClaims))
pub type UnstructuredKeycloakClaims = KeycloakClaims<UnstructuredClaims>;

/// Actix Web extractor for standard JWT claims (see [StandardClaims](StandardClaims))
pub type StandardKeycloakClaims = KeycloakClaims<StandardClaims>;

/// Actix Web extractor for Keycloak roles
#[derive(Debug, Clone)]
pub struct KeycloakRoles(Vec<Role>);

impl KeycloakRoles {
    /// Consumes the `KeycloakRoles`, returning its wrapped data
    pub fn into_inner(self) -> Vec<Role> {
        self.0
    }
}

impl Deref for KeycloakRoles {
    type Target = Vec<Role>;

    fn deref(&self) -> &Vec<Role> {
        &self.0
    }
}

impl FromRequest for KeycloakRoles {
    type Error = KeycloakExtractorError;
    type Future = Ready<Result<Self, Self::Error>>;

    fn from_request(
        req: &actix_web::HttpRequest,
        _payload: &mut actix_web::dev::Payload,
    ) -> Self::Future {
        let extensions = req.extensions();
        match extensions.get::<Vec<Role>>() {
            Some(roles) => ready(Ok(Self(roles.to_owned()))),
            None => ready(Err(KeycloakExtractorError::RolesExtraction)),
        }
    }
}
