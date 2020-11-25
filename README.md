# actix-web-middleware-keycloak-auth

[![LICENSE](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
![Build and test](https://github.com/dsferruzza/actix-web-middleware-keycloak-auth/workflows/Build%20and%20test/badge.svg)
![Lint](https://github.com/dsferruzza/actix-web-middleware-keycloak-auth/workflows/Lint/badge.svg)
[![Crates.io Version](https://img.shields.io/crates/v/actix-web-middleware-keycloak-auth.svg)](https://crates.io/crates/actix-web-middleware-keycloak-auth)
[![Documentation](https://docs.rs/actix-web-middleware-keycloak-auth/badge.svg)](https://docs.rs/actix-web-middleware-keycloak-auth)

A middleware for [Actix Web](https://actix.rs/) that handles authentication with a JWT emitted by [Keycloak](https://www.keycloak.org/).

## Features

- Actix Web middleware
- deny HTTP requests that do not provide a valid JWT
- require one or several Keycloak roles to be included in the JWT
- error HTTP responses sent from the middleware can have generic bodies as well as detailed error reasons

## Usage

- [Documentation](https://crates.io/crates/actix-web-middleware-keycloak-auth)
- [Simple example](examples/simple.rs)

## License

MIT License Copyright (c) 2020 David Sferruzza
