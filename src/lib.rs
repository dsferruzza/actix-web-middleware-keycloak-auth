// actix-web-middleware-keycloak-auth
//
// Copyright: 2020, David Sferruzza
// License: MIT

//! # actix-web-middleware-keycloak-auth
//! A middleware for [Actix Web](https://actix.rs/) that handles authentication with a JWT emitted by [Keycloak](https://www.keycloak.org/).
//!
//! ## Setup middleware
//!
//! Setting up the middleware is done in 2 steps:
//! 1. creating a `KeycloakAuth` struct with the wanted configuration
//! 2. passing this struct to an Actix Web service `wrap()` method
//!
//! ```
//! use actix_web::{App, web, HttpResponse};
//! use actix_web_middleware_keycloak_auth::{KeycloakAuth, DecodingKey};
//!
//! # const KEYCLOAK_PK: &str = "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnzyis1ZjfNB0bBgKFMSv\nvkTtwlvBsaJq7S5wA+kzeVOVpVWwkWdVha4s38XM/pa/yr47av7+z3VTmvDRyAHc\naT92whREFpLv9cj5lTeJSibyr/Mrm/YtjCZVWgaOYIhwrXwKLqPr/11inWsAkfIy\ntvHWTxZYEcXLgAXFuUuaS3uF9gEiNQwzGTU1v0FqkqTBr4B8nW3HCN47XUu0t8Y0\ne+lf4s4OxQawWD79J9/5d3Ry0vbV3Am1FtGJiJvOwRsIfVChDpYStTcHTCMqtvWb\nV6L11BWkpzGXSW4Hv43qa+GSYOD2QU68Mb59oSk2OB+BtOLpJofmbGEGgvmwyCI9\nMwIDAQAB\n-----END PUBLIC KEY-----";
//! // const KEYCLOAK_PK: &str = "..."; // You should get this from configuration
//!
//! // Initialize middleware configuration
//! let keycloak_auth = KeycloakAuth {
//!     detailed_responses: true,
//!     keycloak_oid_public_key: DecodingKey::from_rsa_pem(KEYCLOAK_PK.as_bytes()).unwrap(),
//!     required_roles: vec![],
//! };
//!
//! App::new()
//!     .service(
//!         web::scope("/private")
//!             .wrap(keycloak_auth) // Every route in the service will leverage the middleware
//!             .route("", web::get().to(|| HttpResponse::Ok().body("Private"))),
//!     )
//!     .service(web::resource("/").to(|| HttpResponse::Ok().body("Hello World")));
//! ```
//!
//! HTTP requests to `GET /private` will need to have a `Authorization` header containing `Bearer [JWT]` where `[JWT]` is a valid JWT that was signed by the private key associated with the public key provided when the middleware was initialized.
//!
//! ## Require roles
//!
//! You can require one or several specific roles to be included in JWT.
//! If they are not provided, the middleware will return a 403 error.
//!
//! ```
//! # use actix_web_middleware_keycloak_auth::{KeycloakAuth, DecodingKey, Role};
//! # const KEYCLOAK_PK: &str = "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnzyis1ZjfNB0bBgKFMSv\nvkTtwlvBsaJq7S5wA+kzeVOVpVWwkWdVha4s38XM/pa/yr47av7+z3VTmvDRyAHc\naT92whREFpLv9cj5lTeJSibyr/Mrm/YtjCZVWgaOYIhwrXwKLqPr/11inWsAkfIy\ntvHWTxZYEcXLgAXFuUuaS3uF9gEiNQwzGTU1v0FqkqTBr4B8nW3HCN47XUu0t8Y0\ne+lf4s4OxQawWD79J9/5d3Ry0vbV3Am1FtGJiJvOwRsIfVChDpYStTcHTCMqtvWb\nV6L11BWkpzGXSW4Hv43qa+GSYOD2QU68Mb59oSk2OB+BtOLpJofmbGEGgvmwyCI9\nMwIDAQAB\n-----END PUBLIC KEY-----";
//! let keycloak_auth = KeycloakAuth {
//!     detailed_responses: true,
//!     keycloak_oid_public_key: DecodingKey::from_rsa_pem(KEYCLOAK_PK.as_bytes()).unwrap(),
//!     required_roles: vec![
//!         Role::Realm { role: "admin".to_owned() }, // The "admin" realm role must be provided in the JWT
//!         Role::Client {
//!             client: "backoffice".to_owned(),
//!             role: "readonly".to_owned()
//!         }, // The "readonly" role of the "backoffice" client must be provided in the JWT
//!     ],
//! };
//! ```
//!
//! There is also a [KeycloakRoles](KeycloakRoles) extractor that can be used to get the list of roles extracted from the JWT.
//! This can be useful if a handler must have a different behavior depending of whether a role is present or not (i.e. a role is not stricly necessary but you want to check if it is there anyway, without having to reparse the JWT).
//! Doing this will give your handler a [Vec](Vec) of [Role](Role).
//!
//! ```
//! use actix_web::{HttpResponse, Responder};
//! use actix_web_middleware_keycloak_auth::{KeycloakRoles, Role};
//!
//! async fn private(roles: KeycloakRoles) -> impl Responder {
//!     let roles: &Vec<Role> = &roles;
//!     HttpResponse::Ok().body(format!("{:?}", roles))
//! }
//! ```
//!
//! ## Use several authentication profiles
//!
//! It is possible to setup multiple authentication profiles if, for example, multiple groups of routes require different roles.
//!
//! ```
//! use actix_web::{App, web, HttpResponse};
//! use actix_web_middleware_keycloak_auth::{KeycloakAuth, DecodingKey, Role};
//!
//! # const KEYCLOAK_PK: &str = "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnzyis1ZjfNB0bBgKFMSv\nvkTtwlvBsaJq7S5wA+kzeVOVpVWwkWdVha4s38XM/pa/yr47av7+z3VTmvDRyAHc\naT92whREFpLv9cj5lTeJSibyr/Mrm/YtjCZVWgaOYIhwrXwKLqPr/11inWsAkfIy\ntvHWTxZYEcXLgAXFuUuaS3uF9gEiNQwzGTU1v0FqkqTBr4B8nW3HCN47XUu0t8Y0\ne+lf4s4OxQawWD79J9/5d3Ry0vbV3Am1FtGJiJvOwRsIfVChDpYStTcHTCMqtvWb\nV6L11BWkpzGXSW4Hv43qa+GSYOD2QU68Mb59oSk2OB+BtOLpJofmbGEGgvmwyCI9\nMwIDAQAB\n-----END PUBLIC KEY-----";
//! // const KEYCLOAK_PK: &str = "..."; // You should get this from configuration
//!
//! // No role required
//! let keycloak_auth = KeycloakAuth {
//!     detailed_responses: true,
//!     keycloak_oid_public_key: DecodingKey::from_rsa_pem(KEYCLOAK_PK.as_bytes()).unwrap(),
//!     required_roles: vec![],
//! };
//!
//! // Admin realm role is required
//! let keycloak_auth_admin = KeycloakAuth {
//!     detailed_responses: true,
//!     keycloak_oid_public_key: DecodingKey::from_rsa_pem(KEYCLOAK_PK.as_bytes()).unwrap(),
//!     required_roles: vec![Role::Realm { role: "admin".to_owned() }],
//! };
//!
//! App::new()
//!     .service(
//!         web::scope("/private")
//!             .wrap(keycloak_auth) // User must be authenticated
//!             .route("", web::get().to(|| HttpResponse::Ok().body("Private"))),
//!     )
//!     .service(
//!         web::scope("/admin")
//!             .wrap(keycloak_auth_admin) // User must have the "admin" role
//!             .route("", web::get().to(|| HttpResponse::Ok().body("Admin"))),
//!     )
//!     .service(web::resource("/").to(|| HttpResponse::Ok().body("Hello World")));
//! ```
//!
//! ## Access claims from handlers
//!
//! When authentication is successful, the middleware will store the decoded JWT claims so that they can be accessed from handlers.
//!
//! We provide the [KeycloakClaims](KeycloakClaims) as an Actix Web extractor, which means you can use it as a handler's parameter to obtain claims.
//! This extractor requires a type parameter: it is the struct you want claims to be deserialized into.
//! This struct must implement Serde's [Deserialize](Deserialize) trait.
//!
//! ```
//! use actix_web::{HttpResponse, Responder};
//! use actix_web_middleware_keycloak_auth::KeycloakClaims;
//! use serde::Deserialize;
//!
//! #[derive(Debug, Deserialize)]
//! pub struct MyClaims {
//!   any_fields: u32,
//!   that_money: String,
//!   can_buy: Vec<String>,
//! }
//!
//! async fn private(claims: KeycloakClaims<MyClaims>) -> impl Responder {
//!     HttpResponse::Ok().body(format!("{:?}", &claims))
//! }
//! ```
//!
//! ### Standard claims
//!
//! We provide the [StandardKeycloakClaims](StandardKeycloakClaims) type as a convenience extractor for standard JWT claims.
//! It is equivalent as using the `KeycloakClaims<StandardClaims>` extractor.
//! Check [StandardClaims](StandardClaims) to see which claims are extracted.
//!
//! ```
//! use actix_web::{HttpResponse, Responder};
//! use actix_web_middleware_keycloak_auth::StandardKeycloakClaims;
//!
//! async fn private(claims: StandardKeycloakClaims) -> impl Responder {
//!     HttpResponse::Ok().body(format!("{:?}", &claims))
//! }
//! ```
//!
//! ### All claims
//!
//! It is possible, using the [UnstructuredKeycloakClaims](UnstructuredKeycloakClaims) extractor, to get all provided claim in a semi-structured [HashMap](HashMap).
//! This can be useful when you want to dynamically explore claims (i.e. claims' structure is not fixed).
//!
//! ```
//! use actix_web::{HttpResponse, Responder};
//! use actix_web_middleware_keycloak_auth::UnstructuredKeycloakClaims;
//! use std::collections::HashMap;
//!
//! async fn private(unstructured_claims: UnstructuredKeycloakClaims) -> impl Responder {
//!     let claims: &HashMap<String, serde_json::Value> = &unstructured_claims;
//!     HttpResponse::Ok().body(format!("{:?}", claims))
//! }
//! ```
//!
//! As a convenience method, it is also possible to extract and parse at once a given claim.
//! The target type must implement [Deserialize](Deserialize).
//! If something fails, the returned [Result](Result) will contain a [ClaimError](ClaimError) enum that can tell which one of the extraction or parsing step failed (and why).
//!
//! ```
//! use actix_web::{HttpResponse, Responder};
//! use actix_web_middleware_keycloak_auth::UnstructuredKeycloakClaims;
//! use std::collections::HashMap;
//!
//! async fn private(unstructured_claims: UnstructuredKeycloakClaims) -> impl Responder {
//!     let some_claim = unstructured_claims.get::<Vec<String>>("some_claim");
//!     HttpResponse::Ok().body(format!("{:?}", &some_claim))
//! }
//! ```

// Force exposed items to be documented
#![deny(missing_docs)]

mod errors;
mod extractors;
mod roles;

/// _(Re-exported from the `jsonwebtoken` crate)_
pub use jsonwebtoken::DecodingKey;

use actix_web::body::AnyBody;
use actix_web::dev::{Service, ServiceRequest, ServiceResponse, Transform};
use actix_web::{Error, HttpMessage, HttpResponse};
use chrono::{serde::ts_seconds, DateTime, Utc};
use futures_util::future::{ok, ready, Ready};
use jsonwebtoken::{decode, decode_header, Validation};
use log::{debug, trace};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::{from_value, Value};
use std::collections::HashMap;
use std::future::Future;
use std::ops::Deref;
use std::pin::Pin;
use std::task::{Context, Poll};
use uuid::Uuid;

use errors::AuthError;
pub use errors::ClaimError;
pub use extractors::{
    KeycloakClaims, KeycloakRoles, StandardKeycloakClaims, UnstructuredKeycloakClaims,
};
use roles::{check_roles, extract_roles, Roles};

/// Middleware configuration
#[derive(Debug, Clone)]
pub struct KeycloakAuth<'a> {
    /// If true, error responses will be more detailed to explain what went wrong
    pub detailed_responses: bool,
    /// Public key to use to verify JWT
    pub keycloak_oid_public_key: DecodingKey<'a>,
    /// List of Keycloak roles that must be included in JWT
    pub required_roles: Vec<Role>,
}

impl<'a, S> Transform<S, ServiceRequest> for KeycloakAuth<'a>
where
    S: Service<ServiceRequest, Response = ServiceResponse<AnyBody>, Error = Error>,
    S::Future: 'static,
{
    type Response = ServiceResponse<AnyBody>;
    type Error = Error;
    type InitError = ();
    type Transform = KeycloakAuthMiddleware<'a, S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        trace!("Initialize KeycloakAuthMiddleware");
        ok(KeycloakAuthMiddleware {
            service,
            detailed_responses: self.detailed_responses,
            keycloak_oid_public_key: self.keycloak_oid_public_key.clone(),
            required_roles: self.required_roles.clone(),
        })
    }
}

/// Internal middleware configuration
pub struct KeycloakAuthMiddleware<'a, S> {
    service: S,
    detailed_responses: bool,
    keycloak_oid_public_key: DecodingKey<'a>,
    required_roles: Vec<Role>,
}

/// Standard JWT claims
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct StandardClaims {
    /// Subject (usually, the user ID)
    pub sub: Uuid,
    /// Expiration date
    #[serde(with = "ts_seconds")]
    pub exp: DateTime<Utc>,
    /// Optional realm roles from Keycloak
    pub realm_access: Option<Access>,
    /// Optional client roles from Keycloak
    pub resource_access: Option<HashMap<String, Access>>,
    /// Issuer
    pub iss: String,
    /// Audience
    ///
    /// _This can be extracted from either a JSON string or a JSON sequence of strings._
    #[serde(default, deserialize_with = "deserialize_optional_string_or_strings")]
    pub aud: Option<Vec<String>>,
    /// Issuance date
    #[serde(with = "ts_seconds")]
    pub iat: DateTime<Utc>,
    /// ID of the JWT
    pub jti: Uuid,
    /// Authorized party
    pub azp: String,
}

fn deserialize_optional_string_or_strings<'de, D>(de: D) -> Result<Option<Vec<String>>, D::Error>
where
    D: ::serde::Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum StringOrVec {
        String(String),
        Vec(Vec<String>),
    }

    Option::<StringOrVec>::deserialize(de).map(|string_or_vec| match string_or_vec {
        Some(StringOrVec::String(string)) => Some(vec![string]),
        Some(StringOrVec::Vec(vec)) => Some(vec),
        None => None,
    })
}

impl Default for StandardClaims {
    fn default() -> Self {
        use chrono::Duration;
        use std::ops::Add;

        Self {
            sub: Uuid::from_u128_le(0),
            exp: Utc::now().add(Duration::minutes(1)),
            realm_access: None,
            resource_access: None,
            iss: env!("CARGO_PKG_NAME").to_owned(),
            aud: Some(vec!["account".to_owned()]),
            iat: Utc::now(),
            jti: Uuid::from_u128_le(22685491128062564230891640495451214097),
            azp: "".to_owned(),
        }
    }
}

impl Roles for StandardClaims {
    fn roles(&self) -> Vec<Role> {
        extract_roles(&self.realm_access, &self.resource_access)
    }
}

/// Access details
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Access {
    /// Roles
    pub roles: Vec<String>,
}

/// A realm or client role
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(tag = "type")]
pub enum Role {
    /// A realm role
    Realm {
        /// Name of the role
        role: String,
    },
    /// A client role
    Client {
        /// Client ID
        client: String,
        /// Name of the role
        role: String,
    },
}

impl std::fmt::Display for Role {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Realm { role } => write!(f, "{}", role),
            Self::Client { client, role } => write!(f, "{}.{}", client, role),
        }
    }
}

/// All claims that were extracted from the JWT in an unstructured way (available as a [HashMap](HashMap))
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(transparent)]
pub struct UnstructuredClaims(HashMap<String, Value>);

impl Deref for UnstructuredClaims {
    type Target = HashMap<String, Value>;

    fn deref(&self) -> &HashMap<String, Value> {
        &self.0
    }
}

impl UnstructuredClaims {
    /// Consumes the `UnstructuredClaims`, returning its wrapped HashMap
    pub fn into_inner(self) -> HashMap<String, Value> {
        self.0
    }

    /// Try to extract and parse a given claim
    pub fn get<T: DeserializeOwned>(&self, key: &str) -> Result<T, ClaimError> {
        self.0
            .get(key)
            .ok_or_else(|| ClaimError::NotFound(key.to_owned()))
            .and_then(|val| {
                from_value(val.to_owned())
                    .map_err(|err| ClaimError::ParseError(key.to_owned(), err))
            })
    }
}

/// All claims that are extracted from JWT in an unstructured way that is easy to deserialize into a custom struct using Serde
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(transparent)]
struct RawClaims(pub Value);

#[derive(Debug, Clone, Deserialize)]
struct RoleClaims {
    /// Optional realm roles from Keycloak
    pub realm_access: Option<Access>,
    /// Optional client roles from Keycloak
    pub resource_access: Option<HashMap<String, Access>>,
}

impl Roles for RoleClaims {
    fn roles(&self) -> Vec<Role> {
        extract_roles(&self.realm_access, &self.resource_access)
    }
}

impl<'a, S> Service<ServiceRequest> for KeycloakAuthMiddleware<'a, S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<AnyBody>, Error = Error>,
    S::Future: 'static,
{
    type Response = ServiceResponse<AnyBody>;
    type Error = Error;
    #[allow(clippy::type_complexity)]
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>>>>;

    fn poll_ready(&self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.service.poll_ready(cx)
    }

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let auth_header = req.headers().get("Authorization");

        match auth_header {
            Some(auth_header_value) => {
                let auth_header_str = auth_header_value.to_str();
                match auth_header_str {
                    Ok(raw_token) => {
                        let token = raw_token.trim_start_matches("Bearer ");
                        debug!("Bearer token was extracted from request headers");

                        match decode_header(token) {
                            Ok(jwt_header) => {
                                debug!("JWT header was decoded");
                                debug!("JWT is using {:?} algorithm", &jwt_header.alg);

                                match decode::<Value>(
                                    token,
                                    &self.keycloak_oid_public_key,
                                    &Validation::new(jwt_header.alg),
                                ) {
                                    Ok(raw_token) => {
                                        debug!("JWT was decoded");

                                        match from_value::<RoleClaims>(raw_token.claims.clone()) {
                                            Ok(role_claims) => {
                                                let roles = role_claims.roles();

                                                match check_roles(&roles, &self.required_roles) {
                                                    Ok(_) => {
                                                        debug!("JWT is valid");

                                                        {
                                                            let mut extensions =
                                                                req.extensions_mut();
                                                            extensions.insert(RawClaims(
                                                                raw_token.claims,
                                                            ));
                                                            extensions.insert(roles);
                                                        }

                                                        Box::pin(self.service.call(req))
                                                    }
                                                    Err(e) => {
                                                        debug!("{}", &e);
                                                        Box::pin(ready(Ok(req.into_response(
                                                            e.to_response(self.detailed_responses),
                                                        ))))
                                                    }
                                                }
                                            }
                                            Err(e) => {
                                                let e = AuthError::RoleParsingError(e.to_string());
                                                debug!("{}", &e);
                                                Box::pin(ready(Ok(req
                                                    .into_response::<AnyBody, HttpResponse>(
                                                        e.to_response(self.detailed_responses),
                                                    ))))
                                            }
                                        }
                                    }
                                    Err(e) => {
                                        let e = AuthError::DecodeError(e.to_string());
                                        debug!("{}", &e);
                                        Box::pin(ready(Ok(req
                                            .into_response::<AnyBody, HttpResponse>(
                                                e.to_response(self.detailed_responses),
                                            ))))
                                    }
                                }
                            }
                            Err(e) => {
                                let e = AuthError::InvalidJwt(e.to_string());
                                debug!("{}", &e);
                                Box::pin(ready(Ok(req.into_response::<AnyBody, HttpResponse>(
                                    e.to_response(self.detailed_responses),
                                ))))
                            }
                        }
                    }
                    Err(_) => {
                        let e = AuthError::InvalidAuthorizationHeader;
                        debug!("{}", &e);
                        Box::pin(ready(Ok(req.into_response::<AnyBody, HttpResponse>(
                            e.to_response(self.detailed_responses),
                        ))))
                    }
                }
            }
            None => {
                let e = AuthError::NoBearerToken;
                debug!("{}", &e);
                Box::pin(ready(Ok(req.into_response::<AnyBody, HttpResponse>(
                    e.to_response(self.detailed_responses),
                ))))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{from_value, json};

    #[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
    struct StringOrVec {
        field: u8,
        #[serde(default, deserialize_with = "deserialize_optional_string_or_strings")]
        string_or_vec: Option<Vec<String>>,
    }

    #[test]
    fn deserialize_string_or_vec_when_vec() {
        let input = json!({
            "field": 1,
            "string_or_vec": ["1", "2"],
        });
        let output = from_value::<StringOrVec>(input);
        assert_eq!(
            output.ok(),
            Some(StringOrVec {
                field: 1,
                string_or_vec: Some(vec!["1".to_owned(), "2".to_owned()]),
            })
        )
    }

    #[test]
    fn deserialize_string_or_vec_when_string() {
        let input = json!({
            "field": 1,
            "string_or_vec": "1",
        });
        let output = from_value::<StringOrVec>(input);
        assert_eq!(
            output.ok(),
            Some(StringOrVec {
                field: 1,
                string_or_vec: Some(vec!["1".to_owned()]),
            })
        )
    }

    #[test]
    fn deserialize_string_or_vec_when_none() {
        let input = json!({
            "field": 1,
        });
        let output = from_value::<StringOrVec>(input);
        dbg!(&output);
        assert_eq!(
            output.ok(),
            Some(StringOrVec {
                field: 1,
                string_or_vec: None,
            })
        )
    }

    #[test]
    fn deserialize_string_or_vec_when_null() {
        let input = json!({
            "field": 1,
            "string_or_vec": null,
        });
        let output = from_value::<StringOrVec>(input);
        dbg!(&output);
        assert_eq!(
            output.ok(),
            Some(StringOrVec {
                field: 1,
                string_or_vec: None,
            })
        )
    }
}
