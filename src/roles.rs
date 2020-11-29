// actix-web-middleware-keycloak-auth
//
// Copyright: 2020, David Sferruzza
// License: MIT

use jsonwebtoken::TokenData;
use log::debug;

use crate::errors::AuthError;
use crate::{Claims, Role};

pub fn check_roles(
    token: TokenData<Claims>,
    required_roles: &[Role],
) -> Result<TokenData<Claims>, AuthError> {
    let roles = token.claims.roles();

    debug!(
        "JWT contains roles: {}",
        &roles
            .iter()
            .map(|r| r.to_string())
            .collect::<Vec<String>>()
            .join(", ")
    );

    let mut missing_roles = vec![];
    for role in required_roles {
        if !roles.contains(&role) {
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
    use jsonwebtoken::{Algorithm, Header};
    use std::collections::HashMap;
    use std::iter::FromIterator;

    use super::*;
    use crate::Access;

    #[test]
    fn no_required_no_provided() {
        let token = TokenData {
            header: Header::new(Algorithm::RS256),
            claims: Claims::default(),
        };
        let required_roles = &[];

        assert!(check_roles(token, required_roles).is_ok());
    }

    #[test]
    fn no_required_some_provided() {
        let token = TokenData {
            header: Header::new(Algorithm::RS256),
            claims: Claims {
                realm_access: Some(Access {
                    roles: vec!["test1".to_owned(), "test2".to_owned()],
                }),
                ..Claims::default()
            },
        };
        let required_roles = &[];

        assert!(check_roles(token, required_roles).is_ok());
    }

    #[test]
    fn some_required_no_provided() {
        let token = TokenData {
            header: Header::new(Algorithm::RS256),
            claims: Claims::default(),
        };
        let required_roles = &[
            Role::Realm {
                role: "test1".to_owned(),
            },
            Role::Realm {
                role: "test2".to_owned(),
            },
        ];

        let result = check_roles(token, required_roles);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            AuthError::MissingRoles(vec![
                Role::Realm {
                    role: "test1".to_owned()
                },
                Role::Realm {
                    role: "test2".to_owned()
                }
            ])
        );
    }

    #[test]
    fn some_required_some_provided() {
        let token = TokenData {
            header: Header::new(Algorithm::RS256),
            claims: Claims {
                realm_access: Some(Access {
                    roles: vec!["test2".to_owned()],
                }),
                ..Claims::default()
            },
        };
        let required_roles = &[
            Role::Realm {
                role: "test1".to_owned(),
            },
            Role::Realm {
                role: "test2".to_owned(),
            },
        ];

        let result = check_roles(token, required_roles);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            AuthError::MissingRoles(vec![Role::Realm {
                role: "test1".to_owned()
            }])
        );
    }

    #[test]
    fn some_required_all_provided() {
        let token = TokenData {
            header: Header::new(Algorithm::RS256),
            claims: Claims {
                realm_access: Some(Access {
                    roles: vec!["test1".to_owned(), "test2".to_owned()],
                }),
                ..Claims::default()
            },
        };
        let required_roles = &[
            Role::Realm {
                role: "test1".to_owned(),
            },
            Role::Realm {
                role: "test2".to_owned(),
            },
        ];

        assert!(check_roles(token, required_roles).is_ok());
    }

    #[test]
    fn some_required_more_provided() {
        let token = TokenData {
            header: Header::new(Algorithm::RS256),
            claims: Claims {
                realm_access: Some(Access {
                    roles: vec!["test1".to_owned(), "test2".to_owned(), "test3".to_owned()],
                }),
                ..Claims::default()
            },
        };
        let required_roles = &[
            Role::Realm {
                role: "test1".to_owned(),
            },
            Role::Realm {
                role: "test2".to_owned(),
            },
        ];

        assert!(check_roles(token, required_roles).is_ok());
    }

    #[test]
    fn client_roles() {
        let token = TokenData {
            header: Header::new(Algorithm::RS256),
            claims: Claims {
                realm_access: Some(Access {
                    roles: vec!["test1".to_owned(), "test2".to_owned()],
                }),
                resource_access: Some(HashMap::from_iter(vec![
                    (
                        "client1".to_owned(),
                        Access {
                            roles: vec!["role1".to_owned(), "role2".to_owned()],
                        },
                    ),
                    (
                        "client2".to_owned(),
                        Access {
                            roles: vec!["role3".to_owned()],
                        },
                    ),
                    ("client3".to_owned(), Access { roles: vec![] }),
                ])),
                ..Claims::default()
            },
        };
        let required_roles = &[
            Role::Realm {
                role: "test1".to_owned(),
            },
            Role::Realm {
                role: "test2".to_owned(),
            },
            Role::Client {
                client: "client1".to_owned(),
                role: "role1".to_owned(),
            },
            Role::Client {
                client: "client1".to_owned(),
                role: "role2".to_owned(),
            },
            Role::Client {
                client: "client2".to_owned(),
                role: "role3".to_owned(),
            },
        ];

        assert!(check_roles(token, required_roles).is_ok());
    }

    #[test]
    fn both_realm_and_client_roles() {
        let token = TokenData {
            header: Header::new(Algorithm::RS256),
            claims: Claims {
                resource_access: Some(HashMap::from_iter(vec![
                    (
                        "client1".to_owned(),
                        Access {
                            roles: vec!["role1".to_owned(), "role2".to_owned()],
                        },
                    ),
                    (
                        "client2".to_owned(),
                        Access {
                            roles: vec!["role3".to_owned()],
                        },
                    ),
                    ("client3".to_owned(), Access { roles: vec![] }),
                ])),
                ..Claims::default()
            },
        };
        let required_roles = &[
            Role::Client {
                client: "client1".to_owned(),
                role: "role1".to_owned(),
            },
            Role::Client {
                client: "client1".to_owned(),
                role: "role2".to_owned(),
            },
            Role::Client {
                client: "client2".to_owned(),
                role: "role3".to_owned(),
            },
        ];

        assert!(check_roles(token, required_roles).is_ok());
    }
}
