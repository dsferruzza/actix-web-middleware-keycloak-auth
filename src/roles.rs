// actix-web-middleware-keycloak-auth
//
// Copyright: 2020, David Sferruzza
// License: MIT

use log::debug;
use std::collections::HashMap;

use super::errors::AuthError;
use super::{Access, Role};

pub fn check_roles(roles: &[Role], required_roles: &[Role]) -> Result<(), AuthError> {
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
        if !roles.contains(role) {
            missing_roles.push(role.clone());
        }
    }

    if missing_roles.is_empty() {
        Ok(())
    } else {
        Err(AuthError::MissingRoles(missing_roles))
    }
}

pub fn extract_roles(
    realm_access: &Option<Access>,
    resource_access: &Option<HashMap<String, Access>>,
) -> Vec<Role> {
    let mut roles = realm_access
        .clone()
        .map(|ra| {
            ra.roles
                .iter()
                .map(|role| Role::Realm {
                    role: role.to_owned(),
                })
                .collect()
        })
        .unwrap_or_else(Vec::new);

    let mut client_roles = resource_access
        .clone()
        .map(|ra| {
            ra.iter()
                .flat_map(|(client_name, r)| {
                    r.roles
                        .iter()
                        .map(|role| Role::Client {
                            client: client_name.to_owned(),
                            role: role.to_owned(),
                        })
                        .collect::<Vec<Role>>()
                })
                .collect()
        })
        .unwrap_or_else(Vec::new);

    roles.append(&mut client_roles);
    roles
}

pub trait Roles {
    /// Extract Keycloak roles
    fn roles(&self) -> Vec<Role>;
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::iter::FromIterator;

    use super::*;
    use crate::Access;

    #[test]
    fn no_required_no_provided() {
        let roles = &[];
        let required_roles = &[];

        assert!(check_roles(roles, required_roles).is_ok());
    }

    #[test]
    fn no_required_some_provided() {
        let roles = &extract_roles(
            &Some(Access {
                roles: vec!["test1".to_owned(), "test2".to_owned()],
            }),
            &None,
        );
        let required_roles = &[];

        assert!(check_roles(roles, required_roles).is_ok());
    }

    #[test]
    fn some_required_no_provided() {
        let roles = &[];
        let required_roles = &[
            Role::Realm {
                role: "test1".to_owned(),
            },
            Role::Realm {
                role: "test2".to_owned(),
            },
        ];

        let result = check_roles(roles, required_roles);
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
        let roles = &extract_roles(
            &Some(Access {
                roles: vec!["test2".to_owned()],
            }),
            &None,
        );
        let required_roles = &[
            Role::Realm {
                role: "test1".to_owned(),
            },
            Role::Realm {
                role: "test2".to_owned(),
            },
        ];

        let result = check_roles(roles, required_roles);
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
        let roles = &extract_roles(
            &Some(Access {
                roles: vec!["test1".to_owned(), "test2".to_owned()],
            }),
            &None,
        );
        let required_roles = &[
            Role::Realm {
                role: "test1".to_owned(),
            },
            Role::Realm {
                role: "test2".to_owned(),
            },
        ];

        assert!(check_roles(roles, required_roles).is_ok());
    }

    #[test]
    fn some_required_more_provided() {
        let roles = &extract_roles(
            &Some(Access {
                roles: vec!["test1".to_owned(), "test2".to_owned(), "test3".to_owned()],
            }),
            &None,
        );
        let required_roles = &[
            Role::Realm {
                role: "test1".to_owned(),
            },
            Role::Realm {
                role: "test2".to_owned(),
            },
        ];

        assert!(check_roles(roles, required_roles).is_ok());
    }

    #[test]
    fn client_roles() {
        let roles = &extract_roles(
            &Some(Access {
                roles: vec!["test1".to_owned(), "test2".to_owned()],
            }),
            &Some(HashMap::from_iter(vec![
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
        );
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

        assert!(check_roles(roles, required_roles).is_ok());
    }

    #[test]
    fn both_realm_and_client_roles() {
        let roles = &extract_roles(
            &None,
            &Some(HashMap::from_iter(vec![
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
        );
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

        assert!(check_roles(roles, required_roles).is_ok());
    }
}
