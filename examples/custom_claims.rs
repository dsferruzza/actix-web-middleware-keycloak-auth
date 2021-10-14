// actix-web-middleware-keycloak-auth
//
// Copyright: 2020, David Sferruzza
// License: MIT

use actix_web::{middleware, web, App, HttpResponse, HttpServer, Responder};
use actix_web_middleware_keycloak_auth::{DecodingKey, KeycloakAuth, KeycloakClaims};
use chrono::serde::ts_seconds;
use chrono::{DateTime, Utc};
use serde::Deserialize;
use uuid::Uuid;

const KEYCLOAK_PK: &str = "-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnzyis1ZjfNB0bBgKFMSv
vkTtwlvBsaJq7S5wA+kzeVOVpVWwkWdVha4s38XM/pa/yr47av7+z3VTmvDRyAHc
aT92whREFpLv9cj5lTeJSibyr/Mrm/YtjCZVWgaOYIhwrXwKLqPr/11inWsAkfIy
tvHWTxZYEcXLgAXFuUuaS3uF9gEiNQwzGTU1v0FqkqTBr4B8nW3HCN47XUu0t8Y0
e+lf4s4OxQawWD79J9/5d3Ry0vbV3Am1FtGJiJvOwRsIfVChDpYStTcHTCMqtvWb
V6L11BWkpzGXSW4Hv43qa+GSYOD2QU68Mb59oSk2OB+BtOLpJofmbGEGgvmwyCI9
MwIDAQAB
-----END PUBLIC KEY-----";
/*
Associated private key is:

-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEAnzyis1ZjfNB0bBgKFMSvvkTtwlvBsaJq7S5wA+kzeVOVpVWw
kWdVha4s38XM/pa/yr47av7+z3VTmvDRyAHcaT92whREFpLv9cj5lTeJSibyr/Mr
m/YtjCZVWgaOYIhwrXwKLqPr/11inWsAkfIytvHWTxZYEcXLgAXFuUuaS3uF9gEi
NQwzGTU1v0FqkqTBr4B8nW3HCN47XUu0t8Y0e+lf4s4OxQawWD79J9/5d3Ry0vbV
3Am1FtGJiJvOwRsIfVChDpYStTcHTCMqtvWbV6L11BWkpzGXSW4Hv43qa+GSYOD2
QU68Mb59oSk2OB+BtOLpJofmbGEGgvmwyCI9MwIDAQABAoIBACiARq2wkltjtcjs
kFvZ7w1JAORHbEufEO1Eu27zOIlqbgyAcAl7q+/1bip4Z/x1IVES84/yTaM8p0go
amMhvgry/mS8vNi1BN2SAZEnb/7xSxbflb70bX9RHLJqKnp5GZe2jexw+wyXlwaM
+bclUCrh9e1ltH7IvUrRrQnFJfh+is1fRon9Co9Li0GwoN0x0byrrngU8Ak3Y6D9
D8GjQA4Elm94ST3izJv8iCOLSDBmzsPsXfcCUZfmTfZ5DbUDMbMxRnSo3nQeoKGC
0Lj9FkWcfmLcpGlSXTO+Ww1L7EGq+PT3NtRae1FZPwjddQ1/4V905kyQFLamAA5Y
lSpE2wkCgYEAy1OPLQcZt4NQnQzPz2SBJqQN2P5u3vXl+zNVKP8w4eBv0vWuJJF+
hkGNnSxXQrTkvDOIUddSKOzHHgSg4nY6K02ecyT0PPm/UZvtRpWrnBjcEVtHEJNp
bU9pLD5iZ0J9sbzPU/LxPmuAP2Bs8JmTn6aFRspFrP7W0s1Nmk2jsm0CgYEAyH0X
+jpoqxj4efZfkUrg5GbSEhf+dZglf0tTOA5bVg8IYwtmNk/pniLG/zI7c+GlTc9B
BwfMr59EzBq/eFMI7+LgXaVUsM/sS4Ry+yeK6SJx/otIMWtDfqxsLD8CPMCRvecC
2Pip4uSgrl0MOebl9XKp57GoaUWRWRHqwV4Y6h8CgYAZhI4mh4qZtnhKjY4TKDjx
QYufXSdLAi9v3FxmvchDwOgn4L+PRVdMwDNms2bsL0m5uPn104EzM6w1vzz1zwKz
5pTpPI0OjgWN13Tq8+PKvm/4Ga2MjgOgPWQkslulO/oMcXbPwWC3hcRdr9tcQtn9
Imf9n2spL/6EDFId+Hp/7QKBgAqlWdiXsWckdE1Fn91/NGHsc8syKvjjk1onDcw0
NvVi5vcba9oGdElJX3e9mxqUKMrw7msJJv1MX8LWyMQC5L6YNYHDfbPF1q5L4i8j
8mRex97UVokJQRRA452V2vCO6S5ETgpnad36de3MUxHgCOX3qL382Qx9/THVmbma
3YfRAoGAUxL/Eu5yvMK8SAt/dJK6FedngcM3JEFNplmtLYVLWhkIlNRGDwkg3I5K
y18Ae9n7dHVueyslrb6weq7dTkYDi3iOYRW8HRkIQh06wEdbxt0shTzAJvvCQfrB
jg/3747WSsf/zBTcHihTRBdAv6OmdhV4/dD5YBfLAkLrd+mX7iE=
-----END RSA PRIVATE KEY-----
*/

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    std::env::set_var("RUST_LOG", "info,actix_web_middleware_keycloak_auth=trace");
    env_logger::init();

    HttpServer::new(|| {
        let keycloak_auth = KeycloakAuth::default_with_pk(
            DecodingKey::from_rsa_pem(KEYCLOAK_PK.as_bytes()).unwrap(),
        );

        App::new()
            .wrap(middleware::Logger::default())
            .service(
                web::scope("/private")
                    .wrap(keycloak_auth)
                    .route("", web::get().to(private)),
            )
            .service(web::resource("/").to(hello_world))
    })
    .bind("127.0.0.1:8080")?
    .workers(1)
    .run()
    .await
}

async fn hello_world() -> impl Responder {
    HttpResponse::Ok().body("Hello world!")
}

// Let's define a struct with only the claims we need (even if they are not standard)
#[derive(Debug, Deserialize)]
pub struct ClaimsWithEmail {
    // Standard claims, we choose the way they should be deserialized
    sub: Uuid,
    #[serde(with = "ts_seconds")]
    exp: DateTime<Utc>,
    // Custom claims
    company_id: u32,
}

// We use this lib's extractor to deserialize the provided JWT into our struct (only if the JWT is valid)
async fn private(claims: KeycloakClaims<ClaimsWithEmail>) -> impl Responder {
    HttpResponse::Ok().body(format!("{:?}", &claims))
}

/*
Valid JWT:

eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoiSm9obiBEb2UiLCJhZG1pbiI6dHJ1ZSwiaWF0IjoxNTE2MjM5MDIyLCJleHAiOjI1MTYyMzkwMjIsImlzcyI6ImFjdGl4LXdlYi1taWRkbGV3YXJlLWtleWNsb2FrLWF1dGgiLCJqdGkiOiI3MjY3NThlYy01ZTRhLTQyNTAtODVlNC05ZjczMGUxZThkODQiLCJhenAiOiIiLCJzdWIiOiIxNDVlNmM4Mi1jMzZlLTQ5ZTItYmQ2My1jMDFmMTgzNTJhMGQiLCJjb21wYW55X2lkIjo0Mn0.Vu2UqLEcZEV3Hw56gCBLCdNl2L6FGSX-aUefo2GiqTJD2zfOHC6baFHs1fEcQMytS81-N4jBFDkGe8CX4lvBZDvofkabyVsnskNaeYzMv_WTiU0LjkTQwxFDkhd-7ImM_L-rsCrpUv9F3tosE7bGToDiJQlY_A4nkSGf1htXxAqH1hMtOyJNTDR6pcDUl7eM3AyddafDQu5A5CrWY1ElRSRQWdCzvXFV6-mUPNsi23wfWOq7Qhlo1oZSye3hyic69k8RJwafKJ6V-GKAUXKHfT57Qs1LH28QTZFbvIh00uEBKOCXuDIWBOU9Fqw1CXY2xwwf_v60PrU3ql0PCdfpsA
*/

/*
Invalid JWT (missing company_id):

eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoiSm9obiBEb2UiLCJhZG1pbiI6dHJ1ZSwiaWF0IjoxNTE2MjM5MDIyLCJleHAiOjI1MTYyMzkwMjIsImlzcyI6ImFjdGl4LXdlYi1taWRkbGV3YXJlLWtleWNsb2FrLWF1dGgiLCJqdGkiOiI3MjY3NThlYy01ZTRhLTQyNTAtODVlNC05ZjczMGUxZThkODQiLCJhenAiOiIiLCJzdWIiOiIxNDVlNmM4Mi1jMzZlLTQ5ZTItYmQ2My1jMDFmMTgzNTJhMGQifQ.A7OKRY_zjWJBFBWkoq-Efzc07_pQDrblE2Q_vtgrPNojoNMvxvyggX5oyhCgxgG6iy9bFN_OcoZ-7G8VqTE7nQR0Yhaui1zsAS7tUbx4H3go_WlQEvkjC07C8UxH5TDJkt13GDV0t01B1D3Q7YxOj2PQpnpqzA_x1Fj1ghT4p8q0odTg0YIh6pR_Fhf6ZLsTNwqfbvaO6231YamuQnHe-HHDLEzdFJfrISR7Q7LH0nTy_c9eypcjcse4702hWsEc_-O8nOPGvkfNZ-Hk0TZqf_64rZwweaHel8MGQOFBaLUKO75Avb_nook2op8PIoO7Tf1fL9tyG_DExhOe-E1hww
*/
