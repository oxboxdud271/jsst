use std::collections::HashMap;
use std::error::Error;
use std::time::Duration;
use reqwest::blocking::{Client as ReqwestClient, Response};
use reqwest::header;
use serde_json::Value;

pub struct VaultClient {
    server_url: String,
    client: ReqwestClient,
}

impl VaultClient {
    fn create_client(token: &String) -> ReqwestClient {
        let mut headers = header::HeaderMap::new();
        let token_str = header::HeaderValue::from_str(token.as_str());
        match token_str {
            Ok(v) => {
                headers.insert("X-Vault-Token", v);
            }
            Err(e) => {
                println!("Invalid Vault Token provided")
            }
        }
        ReqwestClient::builder()
            .timeout(Duration::from_secs(10))
            .default_headers(headers)
            .build()
            .unwrap()
    }

    pub fn new(url: &str) -> VaultClient {
        VaultClient {
            server_url: String::from(url),
            client: ReqwestClient::new(),
        }
    }

    pub fn get_token(&self, role_id: String, secret_id: String) -> Result<String, Box<dyn Error>> {
        let mut body = HashMap::new();
        body.insert("role_id", role_id);
        body.insert("secret_id", secret_id);
        let resp = self.client.post(&self.server_url).json(&body).send()?;
        if !resp.status().is_success() {
            Err("Login failed")?;
        }
        let resp_json: Value = resp.json()?;
        let client_token = resp_json["auth"]["client_token"].as_str().unwrap();
        Ok(String::from(client_token))
    }

    pub fn login_with_token(&mut self, token: String) {
        self.client = VaultClient::create_client(&token);
    }

    pub fn post(&self, path: &String, json: &Value) -> reqwest::Result<Response> {
        let mut uri = String::from(&self.server_url);
        uri.push_str(path.as_str());
        println!("Vault POST: {}", uri);
        self.client.post(uri)
            .json(json)
            .send()
    }

    pub fn get(&self, path: &String) -> reqwest::Result<Response> {
        let mut uri = String::from(&self.server_url);
        uri.push_str(path.as_str());
        println!("Vault GET: {}", uri);
        self.client.get(uri).send()
    }
}