use axum::{
    response::{IntoResponse, Response},
    Json,
};
use core::fmt;
use redis::RedisError;
use reqwest::StatusCode;
use serde::Serialize;
use std::io;
use thiserror::Error;
use time::Duration;
use url::Url;

use crate::oidc::AccessTokenErrorResponse;

#[derive(Debug, Error)]
pub enum AppError {
    #[error("{0} is missing from the configuration")]
    MissingConfigVar(&'static str),
    #[error(transparent)]
    IoError(#[from] io::Error),
    #[error("failed fetching OIDC well-known config from {0} ({1})")]
    OidcWellKnownFetchError(Url, String),
    #[error("failed fetching JWKs from {0} ({1})")]
    JwksFetchError(String, String),
    #[error("Failed connecting to redis ({0})")]
    RedisConnectionError(String),
}

#[derive(Debug)]
enum ReqwestErrorType {
    RedirectError,
    StatusCodeError,
    TimeoutError,
    RequestError,
    BodyError,
    DecodeError,
    Unknown,
}

impl fmt::Display for ReqwestErrorType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl From<&reqwest::Error> for ReqwestErrorType {
    fn from(value: &reqwest::Error) -> Self {
        if value.is_builder() {
            Self::BodyError
        } else if value.is_redirect() {
            Self::RedirectError
        } else if value.is_status() {
            Self::StatusCodeError
        } else if value.is_timeout() {
            Self::TimeoutError
        } else if value.is_request() {
            Self::RequestError
        } else if value.is_connect() {
            Self::RequestError
        } else if value.is_body() {
            Self::BodyError
        } else if value.is_decode() {
            Self::DecodeError
        } else {
            Self::Unknown
        }
    }
}

pub(crate) enum HttpError {
    RedisError(RedisError),
    UrlParseError(url::ParseError, String),
    SessionNotFoundError,
    StateNotFound(String),
    RedirectUriError(Option<String>),
    ReqwestError(reqwest::Error),
    IdTokenDecodeError(jsonwebtoken::errors::Error),
    SerdeJsonError(serde_json::Error, &'static str),
    RefreshExpiresInPast(Duration),
    TokenErrorResponse(reqwest::StatusCode, Url, AccessTokenErrorResponse),
}

impl IntoResponse for HttpError {
    fn into_response(self) -> Response {
        #[derive(Debug, Serialize)]
        struct ErrorResponse {
            message: String,
        }

        let (status, message) = match self {
            Self::SessionNotFoundError => {
                tracing::warn!("no session");
                (StatusCode::UNAUTHORIZED, "unauthorized")
            }
            Self::StateNotFound(state) => {
                tracing::warn!(state, "state not found, possible CSRF");
                (StatusCode::BAD_REQUEST, "bad request")
            }
            Self::RedisError(err) => {
                tracing::error!(%err, kind = ?err.kind(), detail = ?err.detail(), "redis error");
                (StatusCode::INTERNAL_SERVER_ERROR, "internal server error")
            }
            Self::UrlParseError(err, url) => {
                tracing::error!(%err, url, "error parsing URL");
                (StatusCode::INTERNAL_SERVER_ERROR, "internal server error")
            }
            Self::RedirectUriError(host_header) => {
                tracing::warn!(?host_header, "failed constructing redirect URI");
                (StatusCode::BAD_REQUEST, "bad request")
            }
            Self::ReqwestError(err) => {
                let err_type = ReqwestErrorType::from(&err);
                let url = match err.url() {
                    Some(url) => url.to_string(),
                    None => "NO_URL".to_owned(),
                };
                tracing::error!(status = ?err.status(), %err_type, url, "failed at http request");
                (StatusCode::INTERNAL_SERVER_ERROR, "internal server error")
            }
            Self::IdTokenDecodeError(err) => {
                tracing::error!(err_type = ?err.kind(), "error decoding ID Token");
                (StatusCode::INTERNAL_SERVER_ERROR, "internal server error")
            }
            Self::SerdeJsonError(err, context) => {
                tracing::error!(?err, "serde json error: {}", context);
                (StatusCode::INTERNAL_SERVER_ERROR, "internal server error")
            }
            Self::RefreshExpiresInPast(duration) => {
                tracing::error!(%duration, "while trying to persist session, refresh token duration is negative");
                (StatusCode::INTERNAL_SERVER_ERROR, "internal server error")
            }
            Self::TokenErrorResponse(status, url, err_resp) => {
                tracing::error!(%status, %url, ?err_resp, "failed getting access token");
                (StatusCode::INTERNAL_SERVER_ERROR, "internal server error")
            }
        };

        (
            status,
            Json(ErrorResponse {
                message: message.to_owned(),
            }),
        )
            .into_response()
    }
}

impl From<RedisError> for HttpError {
    fn from(value: RedisError) -> Self {
        Self::RedisError(value)
    }
}

impl From<url::ParseError> for HttpError {
    fn from(value: url::ParseError) -> Self {
        Self::UrlParseError(value, "".to_owned())
    }
}

impl From<reqwest::Error> for HttpError {
    fn from(value: reqwest::Error) -> Self {
        Self::ReqwestError(value)
    }
}
