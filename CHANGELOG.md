# Changelog

## unreleased

- support Actix Web 4.0.0-beta.10
- add passthrough policy setting to allow auth to be optional
- add a `KeycloakAuth::default_with_pk()` helper function to initialize the middleware with default settings
- improve extractors error types
- expose a pure function to extract custom JWT claims from an Actix Web request

## v0.4.0-beta.1

- switch to Actix Web 4
- handle extraction and parsing of custom JWT claims
- add a way to access parsed roles from handlers (every Keycloak role contained in the JWT)
- add compatibility with the paperclip crate (under the `paperclip_compat` feature)

## v0.3.0

- allow `aud` claim to be extracted from either a JSON string or a JSON sequence of strings (as stated in the [JWT spec](https://tools.ietf.org/html/rfc7519#section-4.1.3))

## v0.2.0

- support client roles
- add common claims that Keycloak provides by default (`iss`, `aud`, `iat`, `jti` and `azp`)
- change the type of the `sub` claim from `String` to `Uuid`
- improve debug logs

## v0.1.0

Initial release
