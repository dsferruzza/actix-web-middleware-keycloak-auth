// actix-web-middleware-keycloak-auth
//
// Copyright: 2020, David Sferruzza
// License: MIT

use actix_web::http::StatusCode;
use actix_web::web::{Bytes, ReqData};
use actix_web::{test, web, App, HttpResponse, Responder};
use actix_web_middleware_keycloak_auth::{Access, Claims, KeycloakAuth, Role};
use jsonwebtoken::{encode, Algorithm, DecodingKey, EncodingKey, Header};
use serde_json::json;
use std::collections::HashMap;
use std::iter::FromIterator;
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

const KEYCLOAK_KEY: &str = "-----BEGIN RSA PRIVATE KEY-----
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
-----END RSA PRIVATE KEY-----";

const KEYCLOAK_FAKE_KEY: &str = "-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7OLF7vh+1uBp2
lzV2zPK91ZSkBaRIhJKSlc7u9cI3gaNUxdDUbsRBpcq6YPcI4pJ/NdcYfTpWl+sH
ER0UBlDQiOVmvyKIyTVPUM9PJx+M6KEpZB6BAypWspwstAoaXMUsdmzeCAw7+UZ1
8TtG+aPRsyObP9/N2zzSP7MEp5ZUlOhwdq0ioCtWsp57aEVFZyK/kSfXjtkH5HHS
aRPHDoG3SrKLKgMMCDz/d8TX06iQU0Ks78yJRgV+7586B/zKigx9z6HOnYVk1q4/
wuWwpBhNIC6KTgrLOOuZbFEz4B/Ecq0eFs8jb53KDuqKxW/C0KA1cbphMwZgfWj9
nEJ5wqLPAgMBAAECggEAYbnRIxd18+P6pEZ/mNiYKLEw2oE7ZMMWwz9Begh8bX7U
4+4x+IEtHltNPAZbTJ7/+zj+YwETD5pTCyhKtmYpjwC2RfClNSNaGWHEJLv2QxY2
8aUaKxuc4Q5waQE9eM9N+MyEPU2UHUYcGnpmB8FNWquYfXRU/V5gHBs19csItHL0
uA6qx/xrE0GxBwVCym+G+kFWYDLVrn/I43C01w4b7Rx7+I4k69NZS0eb9GLl7MDH
VYe6tC2jQOI13a1tv3ElzEF1uOf4o1TMqolzA3qxT1bKowfIKix8xUFK9OY4kJrH
5Cagw0TNcdQvpaBGU7PJsdIbDNjztNvX2ihNpOywSQKBgQDskg89JVLZjDKF7t6U
F/vzegmfby8no5fU7fC5pr+lKX95xSDz3l6InRVTRfyWXwKXiuQ5N1j1stS9Qpfd
YexcJXQv3+Qj5876YX/zjBjTOyHUFgk6l1zc7Q6O++0hxSgXBUcmu1QjNJhg8WAW
68FhzGStTJ9yQuheulbwRPVAIwKBgQDKmQ9UOJtH/XyRr2LNXqRmVCRlN3nCMIaJ
/sMrShDckx5zn3FMtQsT726+nnF7P1OGyKPzcAll7WzXxmWgtT8zlhBAfKRPmczv
dqzekvyEkRk5+FNOpIKOX0WMWf1pwI4qUFliF+NwDrRco+khV+DMfF/oi/WVrGvi
LJR1rQknZQKBgApF9X90RXrJCdCjJOtNd1WFcTGJRIT2J7vJcXC+ewgTG0QQeXPd
rkFEgQ6StXtaOOSX1X1el/BjibWGVM36WKdPwRHrKR8eC/D3lvTemp1hrgBlzJTM
ye2WJdGzwwJ6a1lEk2htLiQxPoTHNqMILeevVpfoAeyWVzz13pykgfn9AoGAHDla
g1cnes37jqgqUYX/zSmnsFocIkt0UsElG2DEHJZ6RY1O0WrfUjWm7fNQx+S4lCxb
esx+4q5C3YSMH+lgFqWvOeyjT1uTy0BzMMa1WxqDsym/IVOVxJPNMpJO1W6333k2
Go5NZw0FX2qOTdDaRmKFUfY9jk5o8SdYv1QN1GkCgYEAiHcbYQDDEzydsZc8utar
xm0D+lYv8MMinI5OBvAgt5e5/EH26cmYCXFO6axVTFaV3jaXIHQ6xsz7rE2ARTCi
DnJHTnzgW7rQsvhRZ0Pvy5flAv8sLG8MUdnEcWcB+lTkoiTE5BZBKyS4TCMQpYMj
ouKbR7feuMF/qWwW/G6Q/6Q=
-----END PRIVATE KEY-----";

async fn hello_world() -> impl Responder {
    HttpResponse::Ok().body("Hello world!")
}

async fn private(claims: ReqData<Claims>) -> impl Responder {
    HttpResponse::Ok().body(&claims.sub.to_string())
}

fn init_logger() {
    std::env::set_var("RUST_LOG", "trace");
    let _ = env_logger::builder().is_test(true).try_init();
}

#[actix_rt::test]
async fn unprotected_route() {
    init_logger();

    let keycloak_auth = KeycloakAuth {
        detailed_responses: true,
        keycloak_oid_public_key: DecodingKey::from_rsa_pem(KEYCLOAK_PK.as_bytes()).unwrap(),
        required_roles: vec![],
    };
    let mut app = test::init_service(
        App::new()
            .service(
                web::scope("/private")
                    .wrap(keycloak_auth)
                    .route("", web::get().to(private)),
            )
            .service(web::resource("/").to(hello_world)),
    )
    .await;

    let req = test::TestRequest::with_uri("/").to_request();
    let resp = test::call_service(&mut app, req).await;

    assert!(resp.status().is_success());
}

#[actix_rt::test]
async fn no_bearer_token() {
    init_logger();

    let keycloak_auth = KeycloakAuth {
        detailed_responses: true,
        keycloak_oid_public_key: DecodingKey::from_rsa_pem(KEYCLOAK_PK.as_bytes()).unwrap(),
        required_roles: vec![],
    };
    let mut app = test::init_service(
        App::new()
            .service(
                web::scope("/private")
                    .wrap(keycloak_auth)
                    .route("", web::get().to(private)),
            )
            .service(web::resource("/").to(hello_world)),
    )
    .await;

    let req = test::TestRequest::with_uri("/private").to_request();
    let resp = test::call_service(&mut app, req).await;

    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let body = test::read_body(resp).await;
    assert!(!body.is_empty());
}

#[actix_rt::test]
async fn no_bearer_token_no_debug() {
    init_logger();

    let keycloak_auth = KeycloakAuth {
        detailed_responses: false,
        keycloak_oid_public_key: DecodingKey::from_rsa_pem(KEYCLOAK_PK.as_bytes()).unwrap(),
        required_roles: vec![],
    };
    let mut app = test::init_service(
        App::new()
            .service(
                web::scope("/private")
                    .wrap(keycloak_auth)
                    .route("", web::get().to(private)),
            )
            .service(web::resource("/").to(hello_world)),
    )
    .await;

    let req = test::TestRequest::with_uri("/private").to_request();
    let resp = test::call_service(&mut app, req).await;

    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let body = test::read_body(resp).await;
    assert_eq!(body, StatusCode::UNAUTHORIZED.to_string());
}

#[actix_rt::test]
async fn no_bearer_in_authorization_header() {
    init_logger();

    let keycloak_auth = KeycloakAuth {
        detailed_responses: true,
        keycloak_oid_public_key: DecodingKey::from_rsa_pem(KEYCLOAK_PK.as_bytes()).unwrap(),
        required_roles: vec![],
    };
    let mut app = test::init_service(
        App::new()
            .service(
                web::scope("/private")
                    .wrap(keycloak_auth)
                    .route("", web::get().to(private)),
            )
            .service(web::resource("/").to(hello_world)),
    )
    .await;

    let req = test::TestRequest::with_uri("/private")
        .header("Authorization", "test")
        .to_request();
    let resp = test::call_service(&mut app, req).await;

    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let body = test::read_body(resp).await;
    assert!(!body.is_empty());
}

#[actix_rt::test]
async fn invalid_jwt() {
    init_logger();

    let keycloak_auth = KeycloakAuth {
        detailed_responses: true,
        keycloak_oid_public_key: DecodingKey::from_rsa_pem(KEYCLOAK_PK.as_bytes()).unwrap(),
        required_roles: vec![],
    };
    let mut app = test::init_service(
        App::new()
            .service(
                web::scope("/private")
                    .wrap(keycloak_auth)
                    .route("", web::get().to(private)),
            )
            .service(web::resource("/").to(hello_world)),
    )
    .await;

    let req = test::TestRequest::with_uri("/private")
        .header("Authorization", "Bearer test")
        .to_request();
    let resp = test::call_service(&mut app, req).await;

    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let body = test::read_body(resp).await;
    assert!(!body.is_empty());
}

#[actix_rt::test]
async fn invalid_jwt_signature() {
    init_logger();

    let keycloak_auth = KeycloakAuth {
        detailed_responses: true,
        keycloak_oid_public_key: DecodingKey::from_rsa_pem(KEYCLOAK_PK.as_bytes()).unwrap(),
        required_roles: vec![],
    };
    let mut app = test::init_service(
        App::new()
            .service(
                web::scope("/private")
                    .wrap(keycloak_auth)
                    .route("", web::get().to(private)),
            )
            .service(web::resource("/").to(hello_world)),
    )
    .await;

    let claims = Claims::default();
    let jwt = encode(
        &Header::new(Algorithm::RS256),
        &claims,
        &EncodingKey::from_rsa_pem(KEYCLOAK_FAKE_KEY.as_bytes()).unwrap(),
    )
    .unwrap();
    let req = test::TestRequest::with_uri("/private")
        .header("Authorization", format!("Bearer {}", &jwt))
        .to_request();
    let resp = test::call_service(&mut app, req).await;

    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let body = test::read_body(resp).await;
    assert!(!body.is_empty());
}

#[actix_rt::test]
async fn valid_jwt() {
    init_logger();

    let keycloak_auth = KeycloakAuth {
        detailed_responses: true,
        keycloak_oid_public_key: DecodingKey::from_rsa_pem(KEYCLOAK_PK.as_bytes()).unwrap(),
        required_roles: vec![],
    };
    let mut app = test::init_service(
        App::new()
            .service(
                web::scope("/private")
                    .wrap(keycloak_auth)
                    .route("", web::get().to(private)),
            )
            .service(web::resource("/").to(hello_world)),
    )
    .await;

    let user_id = Uuid::new_v4();
    let claims = Claims {
        sub: user_id.to_owned(),
        ..Claims::default()
    };
    let jwt = encode(
        &Header::new(Algorithm::RS256),
        &claims,
        &EncodingKey::from_rsa_pem(KEYCLOAK_KEY.as_bytes()).unwrap(),
    )
    .unwrap();
    let req = test::TestRequest::with_uri("/private")
        .header("Authorization", format!("Bearer {}", &jwt))
        .to_request();
    let resp = test::call_service(&mut app, req).await;

    assert!(resp.status().is_success());
    let body = test::read_body(resp).await;
    assert_eq!(body, Bytes::from(user_id.to_string()));
}

#[actix_rt::test]
async fn missing_jwt_roles() {
    init_logger();

    let keycloak_auth = KeycloakAuth {
        detailed_responses: true,
        keycloak_oid_public_key: DecodingKey::from_rsa_pem(KEYCLOAK_PK.as_bytes()).unwrap(),
        required_roles: vec![
            Role::Realm {
                role: "test1".to_owned(),
            },
            Role::Realm {
                role: "test2".to_owned(),
            },
        ],
    };
    let mut app = test::init_service(
        App::new()
            .service(
                web::scope("/private")
                    .wrap(keycloak_auth)
                    .route("", web::get().to(private)),
            )
            .service(web::resource("/").to(hello_world)),
    )
    .await;

    let user_id = Uuid::new_v4();
    let claims = Claims {
        sub: user_id.to_owned(),
        realm_access: Some(Access {
            roles: vec!["test2".to_owned()],
        }),
        ..Claims::default()
    };
    let jwt = encode(
        &Header::new(Algorithm::RS256),
        &claims,
        &EncodingKey::from_rsa_pem(KEYCLOAK_KEY.as_bytes()).unwrap(),
    )
    .unwrap();
    let req = test::TestRequest::with_uri("/private")
        .header("Authorization", format!("Bearer {}", &jwt))
        .to_request();
    let resp = test::call_service(&mut app, req).await;

    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let body = test::read_body(resp).await;
    assert!(!body.is_empty());
}

#[actix_rt::test]
async fn valid_jwt_roles() {
    init_logger();

    let keycloak_auth = KeycloakAuth {
        detailed_responses: true,
        keycloak_oid_public_key: DecodingKey::from_rsa_pem(KEYCLOAK_PK.as_bytes()).unwrap(),
        required_roles: vec![
            Role::Realm {
                role: "test1".to_owned(),
            },
            Role::Realm {
                role: "test2".to_owned(),
            },
            Role::Client {
                client: "client".to_owned(),
                role: "test3".to_owned(),
            },
        ],
    };
    let mut app = test::init_service(
        App::new()
            .service(
                web::scope("/private")
                    .wrap(keycloak_auth)
                    .route("", web::get().to(private)),
            )
            .service(web::resource("/").to(hello_world)),
    )
    .await;

    let user_id = Uuid::new_v4();
    let claims = Claims {
        sub: user_id.to_owned(),
        realm_access: Some(Access {
            roles: vec!["test2".to_owned(), "test1".to_owned()],
        }),
        resource_access: Some(HashMap::from_iter(vec![(
            "client".to_owned(),
            Access {
                roles: vec!["test3".to_owned()],
            },
        )])),
        ..Claims::default()
    };
    let jwt = encode(
        &Header::new(Algorithm::RS256),
        &claims,
        &EncodingKey::from_rsa_pem(KEYCLOAK_KEY.as_bytes()).unwrap(),
    )
    .unwrap();
    let req = test::TestRequest::with_uri("/private")
        .header("Authorization", format!("Bearer {}", &jwt))
        .to_request();
    let resp = test::call_service(&mut app, req).await;

    assert!(resp.status().is_success());
    let body = test::read_body(resp).await;
    assert_eq!(body, Bytes::from(user_id.to_string()));
}

#[actix_rt::test]
async fn from_raw_claims_single_aud_as_string() {
    init_logger();

    let keycloak_auth = KeycloakAuth {
        detailed_responses: true,
        keycloak_oid_public_key: DecodingKey::from_rsa_pem(KEYCLOAK_PK.as_bytes()).unwrap(),
        required_roles: vec![Role::Client {
            client: "client1".to_owned(),
            role: "test1".to_owned(),
        }],
    };
    let mut app = test::init_service(
        App::new()
            .service(
                web::scope("/private")
                    .wrap(keycloak_auth)
                    .route("", web::get().to(private)),
            )
            .service(web::resource("/").to(hello_world)),
    )
    .await;

    let user_id = Uuid::new_v4();
    let default = Claims::default();
    let claims = json!({
        "sub": user_id,
        "resource_access": {
            "client1": {
                "roles": ["test1"],
            },
            "client2": {
                "roles": ["test2"],
            },
        },
        // Defaults
        "exp": default.exp.timestamp(),
        "iss": default.iss,
        "aud": "some-aud",
        "iat": default.iat.timestamp(),
        "jti": default.jti,
        "azp": default.azp,
    });
    let jwt = encode(
        &Header::new(Algorithm::RS256),
        &claims,
        &EncodingKey::from_rsa_pem(KEYCLOAK_KEY.as_bytes()).unwrap(),
    )
    .unwrap();
    let req = test::TestRequest::with_uri("/private")
        .header("Authorization", format!("Bearer {}", &jwt))
        .to_request();
    let resp = test::call_service(&mut app, req).await;

    assert!(resp.status().is_success());
    let body = test::read_body(resp).await;
    assert_eq!(body, Bytes::from(user_id.to_string()));
}
