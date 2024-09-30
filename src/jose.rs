use jsonwebtoken::{jwk::JwkSet, Algorithm, DecodingKey, Validation};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::error::HttpError;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub(crate) struct IdToken {
    #[serde(rename = "sub")]
    pub(crate) subject: String,
    pub(crate) name: String,
    pub(crate) preferred_username: String,
    pub(crate) email: String,
    pub(crate) email_verified: bool,
    #[serde(rename = "exp", with = "time::serde::timestamp")]
    pub(crate) expire: OffsetDateTime,
}

pub(crate) fn verify_id_token(
    token: &str,
    jwk_set: &JwkSet,
    issuer: &String,
) -> Result<IdToken, HttpError> {
    let header =
        jsonwebtoken::decode_header(token).map_err(HttpError::IdTokenDecodeError)?;
    let kid = header.kid.unwrap();

    let jwk = jwk_set.find(&kid).unwrap();
    let key = DecodingKey::from_jwk(jwk).map_err(HttpError::IdTokenDecodeError)?;

    let mut validation = Validation::new(Algorithm::RS256);
    validation.validate_aud = true;
    validation.validate_exp = true;
    validation.validate_nbf = true;
    validation.leeway = 30;
    validation.set_audience(&["bff"]);
    validation.set_issuer(&[&issuer]);
    validation.set_required_spec_claims(&["sub"]);

    Ok(jsonwebtoken::decode(token, &key, &validation)
        .map_err(HttpError::IdTokenDecodeError)?
        .claims)
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct SessionLength {
    #[serde(rename = "exp", with = "time::serde::timestamp")]
    pub(crate) expire: OffsetDateTime,
}