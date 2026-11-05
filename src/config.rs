use serde::Deserialize;
use sigh::{PrivateKey, PublicKey, Key};

#[derive(Clone, Deserialize)]
pub struct RedisConfig {
    pub connection: String,
    pub password_file: String,
    pub in_topic: String,
}

#[derive(Clone, Deserialize)]
pub struct Config {
    /// Seeds the `streams` table on first start; afterwards the table (and
    /// the admin API) decide which streams run.
    #[serde(default)]
    pub streams: Vec<String>,
    pub db: String,
    pub hostname: String,
    pub listen_port: u16,
    pub redis: Option<RedisConfig>,
    /// Loopback port of the admin API; unset = no admin API.
    #[serde(default)]
    pub admin_listen_port: Option<u16>,
    /// File holding the admin bearer token (mode at most 0640, no symlink).
    #[serde(default)]
    pub admin_token_file: Option<String>,
    priv_key_file: String,
    pub_key_file: String,
}

impl Config {
    pub fn load(config_file: &str) -> Config {
        let data = std::fs::read_to_string(config_file)
            .expect("read config");
        serde_yaml::from_str(&data)
            .expect("parse config")
    }

    pub fn priv_key(&self) -> PrivateKey {
        let data = std::fs::read_to_string(&self.priv_key_file)
            .expect("read priv_key_file");
        PrivateKey::from_pem(data.as_bytes())
            .expect("priv_key")
    }

    pub fn pub_key(&self) -> PublicKey {
        let data = std::fs::read_to_string(&self.pub_key_file)
            .expect("read pub_key_file");
        PublicKey::from_pem(data.as_bytes())
            .expect("pub_key")
    }
}
