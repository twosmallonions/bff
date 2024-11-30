use axum::http::HeaderMap;
use axum::Json;
use http::header::{CACHE_CONTROL, SET_COOKIE};
use http::{HeaderName, HeaderValue, StatusCode};
use jsonwebtoken::jwk::JwkSet;
use redis::{aio::MultiplexedConnection, AsyncCommands};
use serde::{Deserialize, Serialize};
use time::{Duration, OffsetDateTime};

use axum::extract::State;
use axum_extra::extract::CookieJar;

use crate::oidc::OidcConfig;
use crate::{
    error::HttpError,
    jose::{self, IdToken},
    make_session_cookie,
    oidc::{self, AccessTokenResponse},
};

use crate::config::SESSION_COOKIE_NAME;
use crate::{make_cache_header, AppState};

#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct Session {
    pub(crate) id_token: IdToken,
    pub(crate) access_token: String,
    pub(crate) refresh_token: String,
    pub(crate) access_expires_at: OffsetDateTime,
    pub(crate) refresh_expires_at: OffsetDateTime,
    pub(crate) created: OffsetDateTime,
    pub(crate) session_id: String,
}

impl Session {
    pub(crate) fn access_expires_in(&self) -> Duration {
        self.access_expires_at - OffsetDateTime::now_utc()
    }

    pub(crate) fn from_access_token_response(
        token_response: AccessTokenResponse,
        jwk_set: &JwkSet,
        issuer: &String,
        session_id: Option<String>,
    ) -> Result<Self, HttpError> {
        tracing::debug!("creating a new session");
        let id_token = jose::verify_id_token(&token_response.id_token, jwk_set, issuer)?;

        let now = OffsetDateTime::now_utc();
        let refresh_expires_in = Duration::SECOND * token_response.refresh_expires_in;
        let session_id = if let Some(s_id) = session_id {
            tracing::debug!(session_id = s_id, %refresh_expires_in, "refresh existing session");
            s_id
        } else {
            let s_id = oidc::make_state();
            tracing::debug!(session_id = s_id, %refresh_expires_in, "created a new session");
            s_id
        };
        Ok(Session {
            session_id,
            access_token: token_response.access_token,
            id_token,
            refresh_token: token_response.refresh_token,
            created: now,
            access_expires_at: now + Duration::SECOND * token_response.expires_in,
            refresh_expires_at: now + refresh_expires_in,
        })
    }

    pub(crate) async fn persist(&self, redis: &mut MultiplexedConnection) -> Result<(), HttpError> {
        let session_str = serde_json::to_string(&self)
            .map_err(|err| HttpError::SerdeJsonError(err, "encoding Session to json string"))?;

        let refresh_expires_in = self.refresh_expires_at - OffsetDateTime::now_utc();
        let refresh_expires_in = refresh_expires_in
            .whole_seconds()
            .try_into()
            .map_err(|_| HttpError::RefreshExpiresInPast(refresh_expires_in))?;
        tracing::debug!(session_id = self.session_id, %refresh_expires_in, "attempting to persist session");
        redis
            .set_ex::<&String, String, ()>(&self.session_id, session_str, refresh_expires_in)
            .await?;

        Ok(())
    }
}

fn get_session_cookie(cookies: &CookieJar) -> Result<&str, HttpError> {
    Ok(cookies
        .get(SESSION_COOKIE_NAME)
        .ok_or(HttpError::SessionNotFoundError)?
        .value_trimmed())
}


async fn get_and_refresh_session(
    http_client: &reqwest::Client,
    oidc_config: &OidcConfig,
    redis: &mut MultiplexedConnection,
    session_id: &str,
) -> Result<Session, HttpError> {
    let session: String = redis.get(session_id).await?;
    let mut session: Session = serde_json::from_str(&session).map_err(|_| HttpError::SessionNotFoundError)?;

    let remaining_session_duration = session.access_expires_at - OffsetDateTime::now_utc();

    if remaining_session_duration.is_negative() || remaining_session_duration.is_zero() {
        tracing::debug!(
            session_id = session.session_id,
            access_expires_at = %session.access_expires_at,
            refresh_expires_at = %session.refresh_expires_at,
            "session expired. Attempting refresh"
        );
        
        session = refresh_session(
            http_client,
            oidc_config,
            redis,
            &session.refresh_token,
            session_id,
        )
        .await?;
    }

    Ok(session)
}

async fn refresh_session(
    http_client: &reqwest::Client, 
    oidc_config: &OidcConfig, 
    redis: &mut MultiplexedConnection,
    refresh_token: &str,
    session_id: &str
) -> Result<Session, HttpError> {
    let access_token_response = oidc::refresh_token(
        http_client,
        oidc_config,
        refresh_token
    )
    .await?;

    let session = Session::from_access_token_response(
        access_token_response,
        &oidc_config.jwk_set,
        &oidc_config.well_known.issuer,
        Some(session_id.to_owned()),
    )?;
    session.persist(redis).await?;

    tracing::debug!(
        session_id = session.session_id,
        access_expires_at = %session.access_expires_at,
        refresh_expires_at = %session.refresh_expires_at,
        "session successfully refreshed"
    );

    Ok(session)
}

pub(crate) async fn check_auth(
    State(mut state): State<AppState>,
    cookies: CookieJar,
) -> Result<(StatusCode, HeaderMap), HttpError> {
    let session_id = get_session_cookie(&cookies)?;
    let session = get_and_refresh_session(
        &state.http_client,
        &state.oidc_config,
        &mut state.redis,
        session_id
    )
    .await?;

    let mut headers = HeaderMap::new();

    headers.insert(
        HeaderName::from_static("x-bff-access-token"),
        HeaderValue::from_str(format!("Bearer {}", session.access_token).as_str()).unwrap(),
    );

    headers.insert(
        CACHE_CONTROL,
        make_cache_header(session.access_expires_in()),
    );

    let session_cookie = make_session_cookie(
        &session.session_id,
        session.refresh_expires_at - OffsetDateTime::now_utc(),
    );
    headers.insert(HeaderName::from_static("X-Bff-Session-Cookie"), session_cookie);
    Ok((http::StatusCode::NO_CONTENT, headers))
}

#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct GetUserinfoResponse {
    sub: String,
    name: String,
    email: String,
}

impl From<IdToken> for GetUserinfoResponse {
    fn from(id_token: IdToken) -> Self {
        GetUserinfoResponse {
            sub: id_token.subject,
            name: id_token.name,
            email: id_token.email,
        }
    }
}

#[axum::debug_handler]
pub(crate) async fn get_userinfo(
    State(mut state): State<AppState>,
    cookies: CookieJar,
) -> Result<Json<GetUserinfoResponse>, HttpError> {
    let session_id = get_session_cookie(&cookies)?;
    let session = get_and_refresh_session(
        &state.http_client,
        &state.oidc_config,
        &mut state.redis,
        session_id
    )
    .await?;

    let userinfo: GetUserinfoResponse = session.id_token.clone().into(); 
    Ok(Json(userinfo))
}