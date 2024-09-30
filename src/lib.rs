use std::time::Duration as StdDuration;

use axum::{
    extract::{MatchedPath, Query, Request, State},
    http::{HeaderMap, HeaderValue},
    response::Redirect,
    routing::get,
    Router, ServiceExt,
};
use axum_extra::extract::cookie::{Cookie, SameSite};
use config::{AppConfig, SESSION_COOKIE_NAME};
use error::{AppError, HttpError};
use jsonwebtoken::jwk::JwkSet;
use redis::{aio::MultiplexedConnection, AsyncCommands, ErrorKind, RedisError};
use reqwest::header::{CACHE_CONTROL, SET_COOKIE};
use serde::Deserialize;
use session::Session;
use time::{Duration, OffsetDateTime};
use tokio::{net::TcpListener, signal};
use tower::{Layer, ServiceBuilder};
use tower_http::normalize_path::NormalizePathLayer;
use tower_http::set_header::SetResponseHeaderLayer;
use tower_http::trace::TraceLayer;
use tower_http::ServiceBuilderExt;
use tower_http::{request_id::MakeRequestUuid, timeout::TimeoutLayer};

pub mod config;
pub mod error;
pub(crate) mod jose;
pub(crate) mod oidc;
pub(crate) mod session;

#[derive(Clone)]
pub(crate) struct AppState {
    oidc_config: oidc::OidcConfig,
    http_client: reqwest::Client,
    app_config: AppConfig,
    redis: MultiplexedConnection,
    jwk_set: JwkSet,
}

async fn redis_connection(config: &config::AppConfig) -> Result<MultiplexedConnection, RedisError> {
    let client = redis::Client::open(config.redis_url.clone())?;

    let conn = client.get_multiplexed_async_connection().await?;

    Ok(conn)
}

pub async fn run(config: config::AppConfig) -> Result<(), AppError> {
    let reqwest_client = reqwest::ClientBuilder::new()
        .timeout(StdDuration::from_secs(10))
        .pool_max_idle_per_host(20)
        .user_agent(concat!("tso-bff/", env!("CARGO_PKG_VERSION")))
        .build()
        .unwrap();

    // FIXME: what is this cloning???
    let mut oidc_well_known_url = config.oidc_issuer.clone();
    oidc_well_known_url
        .path_segments_mut()
        .unwrap()
        .push(".well-known")
        .push("openid-configuration");
    let oidc_well_known = oidc::fetch(oidc_well_known_url.clone(), &reqwest_client)
        .await
        .map_err(|e| {
            AppError::OidcWellKnownFetchError(oidc_well_known_url.clone(), e.to_string())
        })?;

    let jwk_set = oidc::fetch_jwks(&oidc_well_known, &reqwest_client)
        .await
        .map_err(|e| {
            AppError::JwksFetchError(oidc_well_known.jwks_uri.clone().to_string(), e.to_string())
        })?;

    let listen_addr = config.addr.clone();
    let redis = redis_connection(&config)
        .await
        .map_err(|e| AppError::RedisConnectionError(e.to_string()))?;

    let oidc_config = oidc::OidcConfig {
        well_known: oidc_well_known,
        client_credentials: oidc::OidcClientCredentials {
            client_id: config.oidc_client_id.clone(),
            client_secret: config.oidc_client_secret.clone(),
        },
        scopes: config.oidc_scopes.clone(),
        jwk_set: jwk_set.clone(),
    };

    let app_state = AppState {
        oidc_config,
        http_client: reqwest_client,
        app_config: config,
        redis,
        jwk_set,
    };
    let service_builder = ServiceBuilder::new()
        .set_x_request_id(MakeRequestUuid)
        .layer((
            TraceLayer::new_for_http()
                .make_span_with(|req: &Request| {
                    let method = req.method();
                    let uri = req.uri();

                    let matched_path = req
                        .extensions()
                        .get::<MatchedPath>()
                        .map(|matched_path| matched_path.as_str());

                    let request_id = req.headers().get("x-request-id").unwrap().to_str().unwrap();

                    tracing::debug_span!("request", %method, %uri, matched_path, request_id)
                })
                .on_failure(()),
            TimeoutLayer::new(StdDuration::from_secs(10)),
        ))
        .layer(SetResponseHeaderLayer::if_not_present(
            CACHE_CONTROL,
            HeaderValue::from_static("no-cache, no-store, max-age=0, must-revalidate"),
        ));

    let app: Router = Router::new()
        .route("/auth", get(auth))
        .route("/auth/callback", get(auth_callback))
        .route("/auth/userinfo", get(session::get_userinfo))
        .route("/check", get(session::check_auth))
        .layer(service_builder)
        .with_state(app_state);

    let app_with_middleware = NormalizePathLayer::trim_trailing_slash().layer(app);
    let listener = TcpListener::bind(&listen_addr).await?;
    tracing::info!("starting server on {}", &listen_addr);
    axum::serve(
        listener,
        ServiceExt::<Request>::into_make_service(app_with_middleware),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await?;

    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
}

async fn auth(
    State(mut state): State<AppState>,
    headers: HeaderMap,
) -> Result<Redirect, HttpError> {
    let redirect_uri =
        oidc::get_redirect_uri(state.app_config.base_url.as_ref(), headers.get("Host"))?;
    let mut url = state.oidc_config.well_known.authorization_endpoint.clone();

    url.query_pairs_mut().append_pair("response_type", "code");
    url.query_pairs_mut()
        .append_pair("client_id", &state.app_config.oidc_client_id);
    url.query_pairs_mut()
        .append_pair("scope", &state.oidc_config.scopes);
    url.query_pairs_mut()
        .append_pair("redirect_uri", &redirect_uri);

    let auth_state = oidc::make_state();
    url.query_pairs_mut().append_pair("state", &auth_state);

    let code_verifier = oidc::make_code_verifier();
    url.query_pairs_mut()
        .append_pair("code_challenge", &code_verifier.hashed);
    url.query_pairs_mut()
        .append_pair("code_challenge_method", "S256");

    state
        .redis
        .set_ex::<&String, String, ()>(&auth_state, code_verifier.plain, 600)
        .await?;

    Ok(Redirect::to(url.as_str()))
}

#[derive(Debug, Deserialize)]
struct AuthCallbackQueryParams {
    state: String,
    code: String,
}

async fn auth_callback(
    State(mut state): State<AppState>,
    q: Query<AuthCallbackQueryParams>,
    headers: HeaderMap,
) -> Result<HeaderMap, HttpError> {
    let code_verifier = state.redis.get_del::<&String, String>(&q.state).await;
    let code_verifier = match code_verifier {
        Ok(cv) => cv,
        Err(e) => match e.kind() {
            ErrorKind::TypeError => {
                return Err(HttpError::StateNotFound(q.state.clone()));
            }
            _ => {
                return Err(e.into());
            }
        },
    };

    let redirect_uri =
        oidc::get_redirect_uri(state.app_config.base_url.as_ref(), headers.get("Host"))?;
    let token_response = oidc::get_token_response(
        &state.http_client,
        &state.oidc_config,
        &redirect_uri,
        &code_verifier,
        &q.code,
    )
    .await?;
    let session = Session::from_access_token_response(
        token_response,
        &state.jwk_set,
        &state.app_config.oidc_issuer.to_string(),
        None,
    )?;
    session.persist(&mut state.redis).await?;

    let session_cookie = make_session_cookie(
        &session.session_id,
        session.refresh_expires_at - OffsetDateTime::now_utc(),
    );
    let mut response_headers = HeaderMap::with_capacity(1);
    response_headers.append(SET_COOKIE, session_cookie);
    Ok(response_headers)
}

fn make_session_cookie(session_id: &String, expires: Duration) -> HeaderValue {
    let mut session_cookie = Cookie::new(SESSION_COOKIE_NAME, session_id);
    session_cookie.set_path("/");
    session_cookie.set_http_only(true);
    session_cookie.set_same_site(SameSite::Lax);
    session_cookie.set_secure(true);
    session_cookie.set_max_age(expires);
    let session_cookie = session_cookie.to_string();

    HeaderValue::from_str(&session_cookie).unwrap()
}

fn make_cache_header(access_token_expires_in: Duration) -> HeaderValue {
    if access_token_expires_in < Duration::seconds(30) {
        HeaderValue::from_static("max-age=0, no-cache, no-store, must-revalidate")
    } else {
        HeaderValue::from_str(&format!(
            "max-age={}, must-revalidate",
            (access_token_expires_in - Duration::seconds(30)).whole_seconds()
        ))
        .unwrap()
    }
}
