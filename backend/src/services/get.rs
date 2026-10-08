// SPDX-FileCopyrightText: 2023-2026 Sayantan Santra <sayantan.santra689@gmail.com>
// SPDX-License-Identifier: MIT

use actix_web::{
    Either, HttpResponse, Responder, get,
    web::{self, Redirect},
};
use rusqlite::Connection;

use crate::{
    AppState,
    auth::Auth,
    database,
    services::{
        types::{
            BackendConfig,
            ChhotoError::{ClientError, ServerError},
            GetReqParams,
        },
        utils,
    },
};

// Return all active links
#[get("/api/all")]
pub(crate) async fn getall(
    auth: Auth,
    data: web::Data<AppState>,
    params: web::Query<GetReqParams>,
) -> HttpResponse {
    match auth {
        Auth::None { result: _ } => HttpResponse::Unauthorized()
            .content_type("text/plain")
            .body("Unauthorized"),
        Auth::InvalidAPIKey { result } => HttpResponse::Unauthorized()
            .content_type("text/plain")
            .body(result.reason),
        _ => match utils::getall_helper(&data.reader, params.into_inner()) {
            Ok(s) => HttpResponse::Ok().content_type("application/json").body(s),
            Err(ServerError) => HttpResponse::InternalServerError()
                .content_type("text/plain")
                .body("Something went wrong while loading the links.".to_owned()),
            Err(ClientError { reason }) => HttpResponse::BadRequest()
                .content_type("text/plain")
                .body(reason),
        },
    }
}

// Get the site URL
// This is deprecated, and might be removed in the future.
// Use /api/getconfig instead
#[get("/api/siteurl")]
pub(crate) async fn siteurl(data: web::Data<AppState>) -> HttpResponse {
    if let Some(url) = &data.config.site_url {
        HttpResponse::Ok()
            .content_type("text/plain")
            .body(url.clone())
    } else {
        HttpResponse::Ok().content_type("text/plain").body("unset")
    }
}

// Get the version number
// This is deprecated, and might be removed in the future.
// Use /api/getconfig instead
#[get("/api/version")]
pub(crate) async fn version() -> HttpResponse {
    HttpResponse::Ok()
        .content_type("text/plain")
        .body(format!("Chhoto URL v{}", utils::get_version()))
}

// Get the user's current role
#[get("/api/whoami")]
pub(crate) async fn whoami(data: web::Data<AppState>, auth: Auth) -> HttpResponse {
    let config = &data.config;
    let acting_user = match auth {
        Auth::ValidAPIKey | Auth::ValidSession => "admin",
        Auth::NoPass => {
            if config.public_mode {
                "public-nopass"
            } else {
                "nobody-nopass"
            }
        }
        _ => {
            if config.public_mode {
                "public"
            } else {
                "nobody"
            }
        }
    };
    HttpResponse::Ok()
        .content_type("text/plain")
        .body(acting_user)
}

// Get some useful backend config
#[get("/api/getconfig")]
pub(crate) async fn getconfig(data: web::Data<AppState>) -> HttpResponse {
    let config = &data.config;
    let backend_config = BackendConfig {
        version: utils::get_version(),
        allow_capital_letters: config.allow_capital_letters,
        public_mode: config.public_mode,
        public_mode_expiry_delay: config.public_mode_expiry_delay.unwrap_or_default(),
        allowed_protocols: config.allowed_protocols.clone(),
        site_url: config.site_url.clone(),
        slug_style: config.slug_style.to_string(),
        slug_length: config.slug_length,
        try_longer_slug: config.try_longer_slug,
        frontend_page_size: config.frontend_page_size,
        custom_logo_url: config.custom_logo_url.clone(),
        custom_qr_logo_url: config.custom_qr_logo_url.clone(),
        google_auth_enabled: config.google_client_id.is_some() && config.google_client_secret.is_some(),
        disable_password_auth: config.disable_password_auth,
    };
    HttpResponse::Ok().json(backend_config)
}

// Handle a given shortlink
#[get("/{shortlink}")]
pub(crate) async fn link_handler(
    shortlink: web::Path<String>,
    data: web::Data<AppState>,
) -> impl Responder {
    let shortlink_str = shortlink.as_str();
    if let Ok(longlink) =
        database::find_and_add_hit(shortlink_str, &data.reader, &data.hits_tx).await
    {
        if data.config.use_temp_redirect {
            Either::Left(Redirect::to(longlink))
        } else {
            // Defaults to permanent redirection
            Either::Left(Redirect::to(longlink).permanent())
        }
    } else {
        Either::Right(utils::error404(data).await)
    }
}

#[derive(serde::Deserialize)]
pub(crate) struct GoogleCallbackParams {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
}

#[derive(serde::Serialize)]
struct TokenRequest {
    code: String,
    client_id: String,
    client_secret: String,
    redirect_uri: String,
    grant_type: String,
}

#[derive(serde::Deserialize)]
struct TokenResponse {
    access_token: String,
}

#[derive(serde::Deserialize)]
struct UserInfo {
    email: String,
}

#[get("/auth/google/login")]
pub(crate) async fn google_login(data: web::Data<AppState>) -> impl Responder {
    let config = &data.config;
    let (Some(client_id), Some(_client_secret)) = (&config.google_client_id, &config.google_client_secret) else {
        return Either::Left(HttpResponse::BadRequest().body("Google OAuth is not configured."));
    };

    let site_url = config.site_url.clone().unwrap_or_else(|| {
        "http://localhost:4567".to_string()
    });
    let redirect_uri = format!("{}/auth/google/callback", site_url.trim_end_matches('/'));

    let mut auth_url = String::from("https://accounts.google.com/o/oauth2/v2/auth");
    auth_url.push_str("?client_id=");
    auth_url.push_str(&url::form_urlencoded::byte_serialize(client_id.as_bytes()).collect::<String>());
    auth_url.push_str("&redirect_uri=");
    auth_url.push_str(&url::form_urlencoded::byte_serialize(redirect_uri.as_bytes()).collect::<String>());
    auth_url.push_str("&response_type=code");
    auth_url.push_str("&scope=openid%20email%20profile");
    auth_url.push_str("&state=state");

    Either::Right(Redirect::to(auth_url))
}

#[get("/auth/google/callback")]
pub(crate) async fn google_callback(
    params: web::Query<GoogleCallbackParams>,
    session: actix_session::Session,
    data: web::Data<AppState>,
) -> Redirect {
    let config = &data.config;
    let (Some(client_id), Some(client_secret)) = (&config.google_client_id, &config.google_client_secret) else {
        return Redirect::to("/?error=oauth_not_configured");
    };

    if let Some(err) = &params.error {
        log::error!("Google login returned error: {}", err);
        return Redirect::to("/?error=oauth_denied");
    }

    let Some(code) = &params.code else {
        return Redirect::to("/?error=missing_code");
    };

    let site_url = config.site_url.clone().unwrap_or_else(|| {
        "http://localhost:4567".to_string()
    });
    let redirect_uri = format!("{}/auth/google/callback", site_url.trim_end_matches('/'));

    let client = reqwest::Client::new();
    let token_res = match client.post("https://oauth2.googleapis.com/token")
        .form(&TokenRequest {
            code: code.clone(),
            client_id: client_id.clone(),
            client_secret: client_secret.clone(),
            redirect_uri,
            grant_type: "authorization_code".to_string(),
        })
        .send()
        .await {
            Ok(res) => res,
            Err(e) => {
                log::error!("Failed to request token from Google: {}", e);
                return Redirect::to("/?error=token_request_failed");
            }
        };

    if !token_res.status().is_success() {
        let status = token_res.status();
        let err_body = token_res.text().await.unwrap_or_default();
        log::error!("Google token response error status ({}): {}", status, err_body);
        return Redirect::to("/?error=token_exchange_failed");
    }

    let token_response: TokenResponse = match token_res.json().await {
        Ok(res) => res,
        Err(e) => {
            log::error!("Failed to parse Google token response: {}", e);
            return Redirect::to("/?error=token_parse_failed");
        }
    };

    let user_info_res = match client.get("https://www.googleapis.com/oauth2/v3/userinfo")
        .bearer_auth(token_response.access_token)
        .send()
        .await {
            Ok(res) => res,
            Err(e) => {
                log::error!("Failed to fetch userinfo from Google: {}", e);
                return Redirect::to("/?error=user_info_failed");
            }
        };

    if !user_info_res.status().is_success() {
        log::error!("Google userinfo status: {}", user_info_res.status());
        return Redirect::to("/?error=user_info_status_failed");
    }

    let user_info: UserInfo = match user_info_res.json().await {
        Ok(res) => res,
        Err(e) => {
            log::error!("Failed to parse Google userinfo: {}", e);
            return Redirect::to("/?error=user_info_parse_failed");
        }
    };

    let mut email_allowed = config.google_allowed_emails.is_empty();
    if !email_allowed {
        let user_email_lower = user_info.email.to_lowercase();
        for pattern in &config.google_allowed_emails {
            if pattern.starts_with('@') {
                if user_email_lower.ends_with(pattern) {
                    email_allowed = true;
                    break;
                }
            } else if user_email_lower == *pattern {
                email_allowed = true;
                break;
            }
        }
    }

    if !email_allowed {
        log::warn!("Google OAuth login attempted by unauthorized email: {}", user_info.email);
        return Redirect::to("/?error=unauthorized_email");
    }

    // Successfully authenticated, generate session token!
    session.insert("chhoto-url-auth", crate::auth::gen_token_text(true))
        .expect("Error inserting auth token.");

    log::info!("Successful Google login for: {}", user_info.email);
    Redirect::to("/")
}

// Healthcheck endpoint
#[get("/healthz")]
pub(crate) async fn health_handler(db: web::Data<Connection>) -> impl Responder {
    if database::is_database_healthy(&db) {
        HttpResponse::Ok().message_body("healthy")
    } else {
        HttpResponse::InternalServerError().message_body("unhealthy")
    }
}
