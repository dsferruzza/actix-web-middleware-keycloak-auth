use jsonwebtoken::TokenData;
use log::debug;

use crate::errors::AuthError;
use crate::Claims;

pub fn check_roles(
    token: TokenData<Claims>,
    required_roles: &[String],
) -> Result<TokenData<Claims>, AuthError> {
    let roles = token.claims.roles();

    debug!("JWT contains roles: {}", &roles.join(", "));

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
    use chrono::Utc;
    use jsonwebtoken::{Algorithm, Header};

    use super::*;
    use crate::RealmAccess;

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
