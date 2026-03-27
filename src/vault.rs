use reqwest::blocking::{Client as HttpClient, Response};
use reqwest::{header, StatusCode};
use serde_json::{json, Value};
use std::error::Error;
use std::time::Duration;

pub struct VaultClient {
    server_url: String,
    client: reqwest::blocking::Client,

    /// Token that is in X-Vault-Token header.
    /// Should only be used in short scripts where vault is called multiple times
    pub token: String,
}

impl VaultClient {
    fn res(http_res: Result<Response, reqwest::Error>) -> Result<Value, Box<dyn Error>> {
        match http_res {
            Ok(resp) => {
                log::debug!("Vault Response: {}", resp.status());
                match resp.status() {
                    StatusCode::OK => Ok(resp.json()?),
                    StatusCode::NO_CONTENT => Ok(json!({})),
                    e => Err(format!("Vault Response Error {}", e).into()),
                }
            }
            Err(e) => Err(Box::from(e)),
        }
    }

    pub fn post(&self, path: &String, json: &Value) -> Result<Value, Box<dyn Error>> {
        let mut uri = String::from(&self.server_url);
        uri.push_str(path.as_str());
        log::debug!("Vault POST: {}", uri);
        Ok(VaultClient::res(self.client.post(uri).json(json).send())?)
    }

    pub fn get(&self, path: &String) -> Result<Value, Box<dyn Error>> {
        let mut uri = String::from(&self.server_url);
        uri.push_str(path.as_str());
        log::debug!("Vault GET: {}", uri);
        Ok(VaultClient::res(self.client.get(uri).send())?)
    }
}

pub struct VaultClientBuilder {
    token: String,
    url: String,
    auth_mount: String,
}

impl VaultClientBuilder {
    pub fn  new() -> Self {
        Self {
            token: String::new(),
            url: String::new(),
            auth_mount: String::new(),
        }
    }

    pub fn url(self, url: &str) -> Self {
        VaultClientBuilder {
            url: String::from(url),
            ..self
        }
    }

    pub fn token(self, token: &str) -> Self {
        VaultClientBuilder {
            token: String::from(token),
            ..self
        }
    }

    pub fn auth_mount(self, mount: &str) -> Self {
        VaultClientBuilder {
            auth_mount: String::from(mount),
            ..self
        }
    }

    pub fn login(self, role_id: &str, secret_id: &str) -> Result<Self, Box<dyn Error>> {
        let temp_client = HttpClient::new();
        let mut uri = String::from(&self.url);
        uri.push_str(format!("/v1/auth/{}/login", self.auth_mount).as_str());
        let resp = temp_client
            .post(uri)
            .json(&json!({ "role_id": role_id, "secret_id": secret_id }))
            .send()?;
        if !resp.status().is_success() {
            Err("Login failed")?
        }
        let resp_json: Value = resp.json()?;
        let token = resp_json["auth"]["client_token"].as_str().unwrap();
        Ok(VaultClientBuilder {
            token: String::from(token),
            ..self
        })
    }

    pub fn build(self) -> Result<VaultClient, Box<dyn Error>> {
        let mut headers = header::HeaderMap::new();
        let token_str = header::HeaderValue::from_str(&self.token.as_str())?;
        headers.insert("X-Vault-Token", token_str);
        Ok(VaultClient {
            server_url: self.url,
            token: self.token,
            client: HttpClient::builder()
                .timeout(Duration::from_secs(10))
                .default_headers(headers)
                .build()?,
        })
    }
}
