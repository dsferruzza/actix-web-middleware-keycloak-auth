# Examples

Here are several examples of how to use this library.
Each of them is a basic Actix Web application, that has at least one restricted route.

The RS256 public key used to verify JWT tokens is hardcoded in every example.
The associated private key is available as a comment in the source file, so that it is easy to test the lib using tools like [jwt.io](https://jwt.io/).

## Simple

How to run: `cargo run --example simple`

- `http://localhost:8080` is public (no authentication required)
- `http://localhost:8080/private` requires a valid JWT _with standard claims_ **and** the `test` realm role, and responds with a debug string of these claims

## Custom claims

How to run: `cargo run --example custom_claims`

- `http://localhost:8080` is public (no authentication required)
- `http://localhost:8080/private` requires a valid JWT with specific claims we described in a struct, and responds with a debug string of this struct

The following claims are required:
- `sub`: a UUID
- `exp`: a timestamp (in seconds) of the expiration date
+ `company_id`: an unsigned number

## Paperclip

How to run: `cargo run --example paperclip --features paperclip_compat`

This is basically the simple example, but using [paperclip](https://crates.io/crates/paperclip) to generate an OpenAPI documentation.
This spec can be obtain at http://localhost:8080/api/spec.
The main point here is to show that this lib's extractors are compatible with paperclip (no compilation error); they do not change anything related to the generated OpenAPI documentation.
