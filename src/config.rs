
use serde::Deserialize;
use url::Url;

pub(crate) const SESSION_COOKIE_NAME: &str = "__Host-SESSION";

#[derive(Clone, Debug, Deserialize)]
//#[serde(rename_all = "UPPERCASE")]
pub struct AppConfig {
    #[serde(default = "default_listen_addr")]
    pub(crate) addr: String,
    pub(crate) oidc_issuer: Url,
    pub(crate) oidc_client_id: String,
    pub(crate) oidc_client_secret: String,
    pub(crate) oidc_scopes: String,
    pub(crate) redis_url: String,
    pub(crate) base_url: Option<Url>,
}

fn default_listen_addr() -> String {
    "0.0.0.0:8082".to_owned()
}
