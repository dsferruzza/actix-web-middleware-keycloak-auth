use paperclip::actix::OperationModifier;
use paperclip::v2::schema::Apiv2Schema;
use serde::de::DeserializeOwned;

use super::extractors::{KeycloakClaims, KeycloakRoles};

impl<T: DeserializeOwned> Apiv2Schema for KeycloakClaims<T> {}
impl<T: DeserializeOwned> OperationModifier for KeycloakClaims<T> {}

impl Apiv2Schema for KeycloakRoles {}
impl OperationModifier for KeycloakRoles {}
