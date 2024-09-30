use std::collections::HashMap;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use http::HeaderValue;
use jsonwebtoken::jwk::JwkSet;
use rand::{rngs::OsRng, RngCore};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use url::Url;

use crate::error::HttpError;

pub(crate) async fn fetch(
    oidc_config: Url,
    client: &reqwest::Client,
) -> Result<OidcWellKnown, reqwest::Error> {
    let response = client.get(oidc_config).send().await?;
    let oidc_well_known = response.json::<OidcWellKnown>().await?;

    Ok(oidc_well_known)
}

pub(crate) async fn fetch_jwks(
    oidc_well_known: &OidcWellKnown,
    client: &reqwest::Client,
) -> Result<JwkSet, reqwest::Error> {
    client
        .get(oidc_well_known.jwks_uri.clone())
        .send()
        .await?
        .json()
        .await
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub(crate) struct OidcWellKnown {
    pub(crate) issuer: String,
    pub(crate) authorization_endpoint: url::Url,
    pub(crate) token_endpoint: url::Url,
    pub(crate) jwks_uri: url::Url,
}

#[derive(Debug, Clone)]
pub(crate) struct OidcClientCredentials {
    pub(crate) client_id: String,
    pub(crate) client_secret: String,
}

#[derive(Debug, Clone)]
pub(crate) struct OidcConfig {
    pub(crate) well_known: OidcWellKnown,
    pub(crate) client_credentials: OidcClientCredentials,
    pub(crate) scopes: String,
    pub(crate) jwk_set: JwkSet,
}

const PKCE_LENGTH: usize = 32;

#[derive(Debug)]
pub(crate) struct CodeVerifier {
    pub(crate) hashed: String,
    pub(crate) plain: String,
}

pub(crate) fn make_code_verifier() -> CodeVerifier {
    let mut code_verifier_bytes = [0u8; PKCE_LENGTH];
    OsRng::fill_bytes(&mut OsRng, &mut code_verifier_bytes);
    let plain_code_verifier_string = URL_SAFE_NO_PAD.encode(code_verifier_bytes);

    let mut hasher = Sha256::new();
    hasher.update(&plain_code_verifier_string);

    let result = hasher.finalize();

    let hashed_code_verifier_string = URL_SAFE_NO_PAD.encode(result);

    CodeVerifier {
        hashed: hashed_code_verifier_string,
        plain: plain_code_verifier_string,
    }
}

pub(crate) fn make_state() -> String {
    let mut state_bytes = [0u8; 32];
    OsRng::fill_bytes(&mut OsRng, &mut state_bytes);
    URL_SAFE_NO_PAD.encode(state_bytes)
}

pub(crate) fn get_redirect_uri(base_url: Option<&Url>, host_header: Option<&HeaderValue>) -> Result<String, HttpError> {
    if let Some(base_url) = base_url {
        tracing::debug!(%base_url, "constructing redirect_uri from base_url config");
        let mut ret_url = base_url.clone();
        ret_url.set_path("auth/callback");
        Ok(ret_url.to_string())
    } else if let Some(host_header) = host_header {
        let host = host_header
            .to_str()
            .map_err(|_| HttpError::RedirectUriError(Some(format!("{:?}", host_header))))?;

        tracing::debug!(host, "constructing redirect_uri from host header");

        let host_split: Vec<_> = host.split(":").collect();
        let protocol = match host_split
            .first()
            .ok_or_else(|| HttpError::RedirectUriError(Some(format!("{:?}", host))))?
        {
            &"localhost" | &"127.0.0.1" => "http",
            _ => "https",
        };
        Ok(format!("{}://{}/auth/callback", protocol, host))
    } else {
        Err(HttpError::RedirectUriError(None))
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct AccessTokenResponse {
    pub(crate) access_token: String,
    pub(crate) token_type: String,
    pub(crate) id_token: String,
    pub(crate) expires_in: u32,
    pub(crate) refresh_token: String,
    pub(crate) refresh_expires_in: u32,
}

#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct AccessTokenErrorResponse {
    pub(crate) error: String,
    pub(crate) error_description: Option<String>,
    pub(crate) error_uri: Option<String>,
}

async fn get_token(
    client: &Client,
    body: HashMap<&str, &str>,
    token_endpoint: Url,
    client_id: &String,
    client_secret: &String,
) -> Result<AccessTokenResponse, HttpError> {
    let resp = client
        .post(token_endpoint)
        .basic_auth(client_id, Some(client_secret))
        .form(&body)
        .send()
        .await?;

    if !resp.status().is_success() {
        let status = resp.status();
        let url = resp.url().to_owned();
        let err_body: AccessTokenErrorResponse = resp.json().await?;
        Err(HttpError::TokenErrorResponse(status, url, err_body))
    } else {
        Ok(resp.json().await?)
    }
}

pub(crate) async fn get_token_response(
    http_client: &reqwest::Client,
    oidc_config: &OidcConfig,
    redirect_uri: &str,
    code_verifier: &str,
    code: &str,
) -> Result<AccessTokenResponse, HttpError> {
    let mut token_request_body = HashMap::new();
    token_request_body.insert("grant_type", "authorization_code");
    token_request_body.insert("code", code);
    token_request_body.insert("code_verifier", code_verifier);
    token_request_body.insert("redirect_uri", redirect_uri);

    get_token(
        http_client,
        token_request_body,
        oidc_config.well_known.token_endpoint.clone(),
        &oidc_config.client_credentials.client_id,
        &oidc_config.client_credentials.client_secret,
    )
    .await
}

pub(crate) async fn refresh_token(
    http_client: &reqwest::Client,
    oidc_config: &OidcConfig,
    refresh_token: &str,
) -> Result<AccessTokenResponse, HttpError> {
    let mut refresh_token_request_body = HashMap::new();
    refresh_token_request_body.insert("grant_type", "refresh_token");
    refresh_token_request_body.insert("refresh_token", refresh_token);

    get_token(
        http_client,
        refresh_token_request_body,
        oidc_config.well_known.token_endpoint.clone(),
        &oidc_config.client_credentials.client_id,
        &oidc_config.client_credentials.client_secret,
    )
    .await
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_make_code_verifier() {
        let code_verifier = make_code_verifier();

        println!("{:?}", code_verifier)
    }
}
