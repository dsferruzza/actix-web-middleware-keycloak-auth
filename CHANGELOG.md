# Changelog

## v0.3.0

- allow `aud` claim to be extracted from either a JSON string or a JSON sequence of strings (as stated in the [JWT spec](https://tools.ietf.org/html/rfc7519#section-4.1.3))

## v0.2.0

- support client roles
- add common claims that Keycloak provides by default (`iss`, `aud`, `iat`, `jti` and `azp`)
- change the type of the `sub` claim from `String` to `Uuid`
- improve debug logs

## v0.1.0

Initial release
