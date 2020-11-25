// actix-web-middleware-keycloak-auth
//
// Copyright: 2020, David Sferruzza
// License: MIT

//! # actix-web-middleware-keycloak-auth
//! A middleware for Actix Web that handles authentication with a JWT emitted by [Keycloak](https://www.keycloak.org/).
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
//! # use actix_web_middleware_keycloak_auth::{KeycloakAuth, DecodingKey};
//! # const KEYCLOAK_PK: &str = "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnzyis1ZjfNB0bBgKFMSv\nvkTtwlvBsaJq7S5wA+kzeVOVpVWwkWdVha4s38XM/pa/yr47av7+z3VTmvDRyAHc\naT92whREFpLv9cj5lTeJSibyr/Mrm/YtjCZVWgaOYIhwrXwKLqPr/11inWsAkfIy\ntvHWTxZYEcXLgAXFuUuaS3uF9gEiNQwzGTU1v0FqkqTBr4B8nW3HCN47XUu0t8Y0\ne+lf4s4OxQawWD79J9/5d3Ry0vbV3Am1FtGJiJvOwRsIfVChDpYStTcHTCMqtvWb\nV6L11BWkpzGXSW4Hv43qa+GSYOD2QU68Mb59oSk2OB+BtOLpJofmbGEGgvmwyCI9\nMwIDAQAB\n-----END PUBLIC KEY-----";
//! let keycloak_auth = KeycloakAuth {
//!     detailed_responses: true,
//!     keycloak_oid_public_key: DecodingKey::from_rsa_pem(KEYCLOAK_PK.as_bytes()).unwrap(),
//!     required_roles: vec!["admin".to_owned()], // The "admin" role must be provided in the JWT
//! };
//! ```
//!
//! _For now, only realm level roles are supported!_
//!
//! ## Use several authentication profiles
//!
//! It is possible to setup multiple authentication profiles if, for example, multiple groups of routes require different roles.
//!
//! ```
//! use actix_web::{App, web, HttpResponse};
//! use actix_web_middleware_keycloak_auth::{KeycloakAuth, DecodingKey};
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
//! // Admin role is required
//! let keycloak_auth_admin = KeycloakAuth {
//!     detailed_responses: true,
//!     keycloak_oid_public_key: DecodingKey::from_rsa_pem(KEYCLOAK_PK.as_bytes()).unwrap(),
//!     required_roles: vec!["admin".to_owned()],
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
//! ## Access claims in handlers
//!
//! When authentication is successful, the middleware will store the decoded claims so that they can be accessed from handlers.
//!
//! ```
//! use actix_web::web::ReqData;
//! use actix_web::{HttpResponse, Responder};
//! use actix_web_middleware_keycloak_auth::Claims;
//!
//! async fn private(claims: ReqData<Claims>) -> impl Responder {
//!     HttpResponse::Ok().body(format!("{:?}", &claims))
//! }
//! ```

// Force exposed items to be documented
#![deny(missing_docs)]

mod errors;
mod roles;

/// _(Re-exported from the `jsonwebtoken` crate)_
pub use jsonwebtoken::DecodingKey;

use actix_web::dev::{Service, ServiceRequest, ServiceResponse, Transform};
use actix_web::{Error, HttpMessage};
use chrono::{serde::ts_seconds, DateTime, Utc};
use futures_util::future::{ok, ready, Ready};
use jsonwebtoken::{decode, decode_header, Validation};
use log::{debug, trace};
use serde::{Deserialize, Serialize};
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

use errors::AuthError;
use roles::check_roles;

/// Middleware configuration
#[derive(Debug, Clone)]
pub struct KeycloakAuth {
    /// If true, error responses will be more detailed to explain what went wrong
    pub detailed_responses: bool,
    /// Public key to use to verify JWT
    pub keycloak_oid_public_key: DecodingKey<'static>,
    /// List of Keycloak roles that must be included in JWT
    pub required_roles: Vec<String>,
}

impl<S, B> Transform<S> for KeycloakAuth
where
    S: Service<Request = ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static,
{
    type Request = ServiceRequest;
    type Response = ServiceResponse<B>;
    type Error = Error;
    type InitError = ();
    type Transform = KeycloakAuthMiddleware<S>;
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
pub struct KeycloakAuthMiddleware<S> {
    service: S,
    detailed_responses: bool,
    keycloak_oid_public_key: DecodingKey<'static>,
    required_roles: Vec<String>,
}

/// Claims that are extracted from JWT and can be accessed in handlers using a `ReqData<Claims>` parameter
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Claims {
    /// Subject of the JWT (usually, the user ID)
    pub sub: String,
    /// Optional realm roles from Keycloak
    pub realm_access: Option<RealmAccess>,
    /// Expiration date
    #[serde(with = "ts_seconds")]
    pub exp: DateTime<Utc>,
}

impl Claims {
    /// Extract Keycloak roles
    pub fn roles(&self) -> Vec<String> {
        self.realm_access
            .clone()
            .map(|ra| ra.roles)
            .unwrap_or_else(Vec::new)
    }
}

/// Realm-level access details
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RealmAccess {
    /// Realm-level roles
    pub roles: Vec<String>,
}

impl<S, B> Service for KeycloakAuthMiddleware<S>
where
    S: Service<Request = ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static,
{
    type Request = ServiceRequest;
    type Response = ServiceResponse<B>;
    type Error = Error;
    #[allow(clippy::type_complexity)]
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>>>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.service.poll_ready(cx)
    }

    fn call(&mut self, req: ServiceRequest) -> Self::Future {
        let raw_token = req
            .headers()
            .get("Authorization")
            .map(|val| val.to_str().unwrap().trim_start_matches("Bearer "));

        match raw_token {
            Some(token) => {
                debug!("Bearer token was extracted from request headers");

                match decode_header(token) {
                    Ok(jwt_header) => {
                        debug!("JWT header was decoded");
                        debug!("JWT is using {:?} algorithm", &jwt_header.alg);

                        match decode::<Claims>(
                            &token,
                            &self.keycloak_oid_public_key,
                            &Validation::new(jwt_header.alg),
                        ) {
                            Ok(token) => {
                                debug!("JWT was decoded");

                                match check_roles(token, &self.required_roles) {
                                    Ok(token_data) => {
                                        debug!("JWT is valid; putting claims in ReqData");

                                        {
                                            let mut extensions = req.extensions_mut();
                                            extensions.insert(token_data.claims);
                                        }

                                        Box::pin(self.service.call(req))
                                    }
                                    Err(e) => Box::pin(ready(Ok(req.into_response(
                                        e.to_response(self.detailed_responses).into_body(),
                                    )))),
                                }
                            }
                            Err(e) => Box::pin(ready(Ok(req.into_response(
                                AuthError::DecodeError(e.to_string())
                                    .to_response(self.detailed_responses)
                                    .into_body(),
                            )))),
                        }
                    }
                    Err(e) => Box::pin(ready(Ok(req.into_response(
                        AuthError::InvalidJwt(e.to_string())
                            .to_response(self.detailed_responses)
                            .into_body(),
                    )))),
                }
            }
            None => Box::pin(ready(Ok(req.into_response(
                AuthError::NoBearerToken
                    .to_response(self.detailed_responses)
                    .into_body(),
            )))),
        }
    }
}
