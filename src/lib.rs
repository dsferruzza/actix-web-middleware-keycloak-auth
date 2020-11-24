mod errors;

use actix_web::dev::{Service, ServiceRequest, ServiceResponse, Transform};
use actix_web::{Error, HttpMessage};
use chrono::{serde::ts_seconds, DateTime, Utc};
use futures_util::future::{ok, ready, Ready};
use jsonwebtoken::{decode, decode_header, DecodingKey, TokenData, Validation};
use log::{debug, trace};
use serde::Deserialize;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

use errors::AuthError;

#[derive(Debug, Clone)]
pub struct KeycloakAuth {
    pub detailed_responses: bool,
    pub keycloak_oid_public_key: DecodingKey<'static>,
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

pub struct KeycloakAuthMiddleware<S> {
    service: S,
    detailed_responses: bool,
    keycloak_oid_public_key: DecodingKey<'static>,
    required_roles: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub realm_access: Option<RealmAccess>,
    #[serde(with = "ts_seconds")]
    pub exp: DateTime<Utc>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RealmAccess {
    roles: Vec<String>,
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

fn check_roles(
    token: TokenData<Claims>,
    required_roles: &[String],
) -> Result<TokenData<Claims>, AuthError> {
    let realm_roles = token
        .claims
        .clone()
        .realm_access
        .map(|ra| ra.roles)
        .unwrap_or_else(Vec::new);

    debug!("JWT contains roles: {}", &realm_roles.join(", "));

    let mut missing_roles = vec![];
    for role in required_roles {
        if !realm_roles.contains(&role) {
            missing_roles.push(role.clone());
        }
    }

    if missing_roles.is_empty() {
        Ok(token)
    } else {
        Err(AuthError::MissingRoles(missing_roles))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{Algorithm, Header};

    #[test]
    fn no_required_no_provided() {
        let token = TokenData {
            header: Header::new(Algorithm::RS256),
            claims: Claims {
                sub: "".to_owned(),
                exp: Utc::now(),
                realm_access: None,
            },
        };
        let required_roles = &[];

        assert!(check_roles(token, required_roles).is_ok());
    }

    #[test]
    fn no_required_some_provided() {
        let token = TokenData {
            header: Header::new(Algorithm::RS256),
            claims: Claims {
                sub: "".to_owned(),
                exp: Utc::now(),
                realm_access: Some(RealmAccess {
                    roles: vec!["test1".to_owned(), "test2".to_owned()],
                }),
            },
        };
        let required_roles = &[];

        assert!(check_roles(token, required_roles).is_ok());
    }

    #[test]
    fn some_required_no_provided() {
        let token = TokenData {
            header: Header::new(Algorithm::RS256),
            claims: Claims {
                sub: "".to_owned(),
                exp: Utc::now(),
                realm_access: None,
            },
        };
        let required_roles = &["test1".to_owned(), "test2".to_owned()];

        let result = check_roles(token, required_roles);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            AuthError::MissingRoles(vec!["test1".to_owned(), "test2".to_owned()])
        );
    }

    #[test]
    fn some_required_some_provided() {
        let token = TokenData {
            header: Header::new(Algorithm::RS256),
            claims: Claims {
                sub: "".to_owned(),
                exp: Utc::now(),
                realm_access: Some(RealmAccess {
                    roles: vec!["test2".to_owned()],
                }),
            },
        };
        let required_roles = &["test1".to_owned(), "test2".to_owned()];

        let result = check_roles(token, required_roles);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            AuthError::MissingRoles(vec!["test1".to_owned(),])
        );
    }

    #[test]
    fn some_required_all_provided() {
        let token = TokenData {
            header: Header::new(Algorithm::RS256),
            claims: Claims {
                sub: "".to_owned(),
                exp: Utc::now(),
                realm_access: Some(RealmAccess {
                    roles: vec!["test1".to_owned(), "test2".to_owned()],
                }),
            },
        };
        let required_roles = &["test1".to_owned(), "test2".to_owned()];

        assert!(check_roles(token, required_roles).is_ok());
    }

    #[test]
    fn some_required_more_provided() {
        let token = TokenData {
            header: Header::new(Algorithm::RS256),
            claims: Claims {
                sub: "".to_owned(),
                exp: Utc::now(),
                realm_access: Some(RealmAccess {
                    roles: vec!["test1".to_owned(), "test2".to_owned(), "test3".to_owned()],
                }),
            },
        };
        let required_roles = &["test1".to_owned(), "test2".to_owned()];

        assert!(check_roles(token, required_roles).is_ok());
    }
}
