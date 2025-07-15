/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2025. All rights reserved.
 * Global Trust Authority is licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

mod commands;
mod entities;

use crate::commands::{
    BaselineCommands, CertificateCommands, EvidenceCommands, NonceCommands, PolicyCommands, RegisterCommands,
    TokenCommands,
};
use crate::entities::{CertType, ContentType, NonceResponse, TokenResponse};
use agent_utils::load_plugins::load_plugins;
use agent_utils::AgentError;
use base64::{engine::general_purpose, Engine as _};
use challenge::challenge::Nonce;
use challenge::evidence::{EvidenceManager, GetEvidenceRequest};
use clap::{Parser, Subcommand};
use config::config::ConfigManager;
use config::{Config, AGENT_CONFIG};
use lazy_static::lazy_static;
use reqwest::header::HeaderValue;
use reqwest::{Certificate, Client, Identity, StatusCode};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

#[derive(Parser)]
#[clap(author, version, about, long_about = None)]
struct Cli {
    /// Service Url
    #[clap(short, long, default_value = "")]
    server_url: String,

    /// Client CA Cert
    #[clap(long, default_value = "")]
    cert_path: String,

    /// Service CA Cert
    #[clap(long, default_value = "")]
    ca_path: String,

    #[clap(subcommand)]
    group: CommandGroup,

    /// User Id
    #[clap(short, long, default_value = "")]
    user: String,

    /// Api Key
    #[clap(short = 'k', long = "apikey", default_value = "")]
    apikey: String,
}

#[derive(Subcommand)]
enum CommandGroup {
    /// Register
    Register {
        #[clap(subcommand)]
        command: RegisterCommands,
    },

    /// Policy Management
    Policy {
        #[clap(subcommand)]
        command: PolicyCommands,
    },

    /// Certificate Management
    Certificate {
        #[clap(subcommand)]
        command: CertificateCommands,
    },

    /// Baseline Management
    Baseline {
        #[clap(subcommand)]
        command: BaselineCommands,
    },

    /// Nonce Management
    Nonce {
        #[clap(subcommand)]
        command: NonceCommands,
    },

    /// Evidence Management
    Evidence {
        #[clap(subcommand)]
        command: EvidenceCommands,
    },

    /// Attest Management
    Attest {
        /// Message
        #[clap(short, long)]
        message: Option<String>,

        /// Evidence file address
        #[clap(short, long)]
        file: String,

        /// Output file address
        #[clap(short, long)]
        out: Option<String>,
    },

    /// Token Management
    Token {
        #[clap(subcommand)]
        command: TokenCommands,
    },
}

static USER_ID: &str = "User-Id";
static API_KEY: &str = "API-Key";
static AGENT_VERSION: &str = "1.0.0";
static START_STR: &str = "@";
static RPM_CONFIG_PATH: &str = "/etc/attestation_agent/agent_config.yaml";
static SERVICE_URL_PREFIX: &str = "/global-trust-authority/service/v1";

lazy_static! {
    static ref CONFIG_PATH: PathBuf =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).parent().unwrap().join(Path::new("config/agent_config.yaml"));
}

async fn deal_certificate_commands(
    command: &CertificateCommands,
    server_url: String,
    client: Client,
    user: &String,
    apikey: &String,
) {
    let url = format!("{}/cert", &server_url);
    match command {
        CertificateCommands::Set { name, description, cert_type, content, crl_content, is_default } => {
            let request_body = if cert_type.contains(&CertType::Crl) {
                if crl_content.is_none() {
                    eprintln!("when cert-type is crl, the revoke-certificate-file must be filled in");
                    return;
                }
                let name = get_name(name, crl_content);
                let crl_content = get_content(crl_content).unwrap();
                json!({
                    "name": name,
                    "type": cert_type,
                    "crl_content": crl_content,
                })
            } else {
                if content.is_none() {
                    eprintln!("when cert-type is not crl, the file must be filled in");
                    return;
                }
                let name = get_name(name, content);
                let content = get_content(content);
                json!({
                    "name": name,
                    "description": description,
                    "type": cert_type,
                    "content":content,
                    "is_default": is_default,
                })
            };
            let response = client
                .post(url)
                .header(USER_ID, HeaderValue::from_str(user).unwrap())
                .header(API_KEY, HeaderValue::from_str(apikey).unwrap())
                .json(&request_body)
                .send()
                .await
                .unwrap();
            println!("status: {}", response.status());
            println!("body: {}", response.text().await.unwrap());
        },
        CertificateCommands::Delete { delete_type, ids, cert_type } => {
            let request_body = json!({
                "delete_type": delete_type,
                "ids": ids,
                "type": cert_type,
            });
            let response = client
                .delete(url)
                .header(USER_ID, HeaderValue::from_str(user).unwrap())
                .header(API_KEY, HeaderValue::from_str(apikey).unwrap())
                .json(&request_body)
                .send()
                .await
                .unwrap();
            println!("status: {}", response.status());
            println!("body: {}", response.text().await.unwrap());
        },
        CertificateCommands::Update { id, name, description, cert_type, is_default } => {
            let request_body = json!({
                "id": id,
                "name": name,
                "description": description,
                "type": cert_type,
                "is_default": is_default,
            });
            let response = client
                .put(url)
                .header(USER_ID, HeaderValue::from_str(user).unwrap())
                .header(API_KEY, HeaderValue::from_str(apikey).unwrap())
                .json(&request_body)
                .send()
                .await
                .unwrap();
            println!("status: {}", response.status());
            println!("body: {}", response.text().await.unwrap());
        },
        CertificateCommands::Get { cert_type, ids } => {
            let mut params = HashMap::new();
            if let Some(cert_type) = cert_type {
                params.insert("cert_type", json!(cert_type));
            }
            if let Some(ids) = ids {
                params.insert("ids", json!(ids.join(",")));
            }
            let response = client
                .get(url)
                .header(USER_ID, HeaderValue::from_str(user).unwrap())
                .header(API_KEY, HeaderValue::from_str(apikey).unwrap())
                .query(&params)
                .send()
                .await
                .unwrap();
            println!("status: {}", response.status());
            println!("body: {}", response.text().await.unwrap());
        },
    }
}

/// For text type policies, need to be encoded in base64, while for JWT type policies, need to be read out
fn get_policy_content(content: &Option<String>, content_type: &Option<ContentType>) -> Option<String> {
    match (content_type, content) {
        (Some(content_type), Some(content)) => {
            if content.starts_with(START_STR) {
                let file_path = &content[START_STR.len()..];
                Some(match content_type {
                    ContentType::Jwt => fs::read_to_string(file_path).unwrap(),
                    ContentType::Text => {
                        let file_data = fs::read(file_path).unwrap();
                        general_purpose::STANDARD.encode(&file_data)
                    },
                })
            } else {
                Some(match content_type {
                    ContentType::Jwt => content.clone(),
                    ContentType::Text => general_purpose::STANDARD.encode(content),
                })
            }
        },
        _ => None,
    }
}

async fn deal_policy_commands(
    command: &PolicyCommands,
    server_url: String,
    client: Client,
    user: &String,
    apikey: &String,
) {
    let url = format!("{}/policy", &server_url);
    match command {
        PolicyCommands::Set { name, description, attester_type, content_type, content, is_default } => {
            let name = get_name(name, &Some(content.to_string()));
            let content = get_policy_content(&Some(content.to_string()), &Some(content_type.clone()));
            let request_body = json!({
                "name": name,
                "description": description,
                "attester_type": attester_type,
                "content_type":content_type,
                "content": content,
                "is_default": is_default,
            });
            let response = client
                .post(url)
                .header(USER_ID, HeaderValue::from_str(user).unwrap())
                .header(API_KEY, HeaderValue::from_str(apikey).unwrap())
                .json(&request_body)
                .send()
                .await
                .unwrap();
            println!("status: {}", response.status());
            println!("body: {}", response.text().await.unwrap());
        },
        PolicyCommands::Delete { delete_type, ids, attester_type } => {
            let mut request_body = json!({
                "delete_type": delete_type,
            });
            if let Value::Object(ref mut map) = request_body {
                if let Some(ids) = ids {
                    map.insert("ids".to_string(), json!(ids));
                }
                if let Some(attester_type) = attester_type {
                    map.insert("attester_type".to_string(), json!(attester_type));
                }
            }
            let response = client
                .delete(url)
                .header(USER_ID, HeaderValue::from_str(user).unwrap())
                .header(API_KEY, HeaderValue::from_str(apikey).unwrap())
                .json(&request_body)
                .send()
                .await
                .unwrap();
            println!("status: {}", response.status());
            println!("body: {}", response.text().await.unwrap());
        },
        PolicyCommands::Update { id, name, description, attester_type, content_type, content, is_default } => {
            // For text type policies, need to be encoded in base64, while for JWT type policies, need to be read out
            let content = get_policy_content(content, content_type);
            let request_body = json!({
                "id": id,
                "name": name,
                "description": description,
                "attester_type": attester_type,
                "content_type":content_type,
                "content": content,
                "is_default": is_default,
            });
            let response = client
                .put(url)
                .header(USER_ID, HeaderValue::from_str(user).unwrap())
                .header(API_KEY, HeaderValue::from_str(apikey).unwrap())
                .json(&request_body)
                .send()
                .await
                .unwrap();
            println!("status: {}", response.status());
            println!("body: {}", response.text().await.unwrap());
        },
        PolicyCommands::Get { attester_type, ids } => {
            let mut params = HashMap::new();
            if let Some(attester_type) = attester_type {
                params.insert("attester_type", json!(attester_type));
            }
            if let Some(ids) = ids {
                params.insert("ids", json!(ids.join(",")));
            }
            let response = client
                .get(url)
                .header(USER_ID, HeaderValue::from_str(user).unwrap())
                .header(API_KEY, HeaderValue::from_str(apikey).unwrap())
                .query(&params)
                .send()
                .await
                .unwrap();
            println!("status: {}", response.status());
            println!("body: {}", response.text().await.unwrap());
        },
    }
}

fn get_content(content: &Option<String>) -> Option<String> {
    content.as_ref().and_then(|content| {
        if content.starts_with(START_STR) {
            let file_path = &content[START_STR.len()..];
            fs::read_to_string(file_path).ok().map(|s| s.trim_end().to_string())
        } else {
            Some(content.clone())
        }
    })
}

fn get_name(name: &Option<String>, content: &Option<String>) -> Option<String> {
    match (name, content) {
        (Some(name), _) => Some(name.clone()),
        (None, Some(content)) => {
            if !content.starts_with(START_STR) {
                return None;
            }
            let file_path = Path::new(content);
            file_path.file_name().and_then(|os_str| os_str.to_str()).map(|s| s.to_string())
        },
        (None, None) => None,
    }
}

async fn deal_baseline_commands(
    command: &BaselineCommands,
    server_url: String,
    client: Client,
    user: &String,
    apikey: &String,
) {
    let url = format!("{}/ref_value", &server_url);
    match command {
        BaselineCommands::Set { name, description, attester_type, content, is_default } => {
            let name = get_name(name, &Some(content.to_string()));
            let content = get_content(&Some(content.to_string()));
            let request_body = json!({
                "name": name,
                "description": description,
                "attester_type": attester_type,
                "content":content,
                "is_default": is_default,
            });
            let response = client
                .post(url)
                .header(USER_ID, HeaderValue::from_str(user).unwrap())
                .header(API_KEY, HeaderValue::from_str(apikey).unwrap())
                .json(&request_body)
                .send()
                .await
                .unwrap();
            println!("status: {}", response.status());
            println!("body: {}", response.text().await.unwrap());
        },
        BaselineCommands::Delete { delete_type, ids, attester_type } => {
            let request_body = json!({
                "delete_type": delete_type,
                "ids": ids,
                "attester_type": attester_type,
            });
            let response = client
                .delete(url)
                .header(USER_ID, HeaderValue::from_str(user).unwrap())
                .header(API_KEY, HeaderValue::from_str(apikey).unwrap())
                .json(&request_body)
                .send()
                .await
                .unwrap();
            println!("status: {}", response.status());
            println!("body: {}", response.text().await.unwrap());
        },
        BaselineCommands::Update { id, name, description, attester_type, content, is_default } => {
            let content = get_content(content);
            let request_body = json!({
                "id": id,
                "name": name,
                "description": description,
                "attester_type": attester_type,
                "content": content,
                "is_default": is_default,
            });
            let response = client
                .put(url)
                .header(USER_ID, HeaderValue::from_str(user).unwrap())
                .header(API_KEY, HeaderValue::from_str(apikey).unwrap())
                .json(&request_body)
                .send()
                .await
                .unwrap();
            println!("status: {}", response.status());
            println!("body: {}", response.text().await.unwrap());
        },
        BaselineCommands::Get { attester_type, ids } => {
            let mut params = HashMap::new();
            if let Some(attester_type) = attester_type {
                params.insert("attester_type", json!(attester_type));
            }
            if let Some(ids) = ids {
                params.insert("ids", json!(ids.join(",")));
            }
            let response = client
                .get(url)
                .header(USER_ID, HeaderValue::from_str(user).unwrap())
                .header(API_KEY, HeaderValue::from_str(apikey).unwrap())
                .query(&params)
                .send()
                .await
                .unwrap();
            println!("status: {}", response.status());
            println!("body: {}", response.text().await.unwrap());
        },
    }
}

fn get_attester_types(config: Config) -> Vec<String> {
    let mut attester_type = Vec::new();
    for plugin_config in config.plugins {
        if plugin_config.enabled {
            attester_type.push(plugin_config.name);
        }
    }
    attester_type
}

async fn deal_nonce_commands(
    command: &NonceCommands,
    server_url: String,
    client: Client,
    user: &String,
    config: Config,
    apikey: &String,
) {
    let url = format!("{}/challenge", &server_url);
    match command {
        NonceCommands::Get { out } => {
            let attester_type = get_attester_types(config);
            let request_body = json!({
                "agent_version": AGENT_VERSION,
                "attester_type": attester_type,
            });
            let response = client
                .post(url)
                .header(USER_ID, HeaderValue::from_str(user).unwrap())
                .header(API_KEY, HeaderValue::from_str(apikey).unwrap())
                .json(&request_body)
                .send()
                .await
                .unwrap();
            let status = response.status();
            println!("status: {}", status);
            let text = &response.text().await.unwrap();
            if status != StatusCode::OK || out.is_none() {
                println!("body: {}", text);
            }
            if out.is_some() && status == StatusCode::OK {
                let response: NonceResponse = serde_json::from_str(text).unwrap();
                if let Some(nonce) = response.nonce {
                    let nonce_json = serde_json::to_string_pretty(&nonce).expect("Failed to serialize nonce to JSON");
                    let out_path = match out {
                        Some(path) => path,
                        None => {
                            eprintln!("Output path is None, skipping file write");
                            return;
                        },
                    };
                    if let Err(e) = fs::create_dir_all(Path::new(&out_path).parent().unwrap()) {
                        eprintln!("Warning: Failed to create directories for {}: {}", out_path, e);
                        return;
                    }
                    match fs::write(&out_path, &nonce_json) {
                        Ok(_) => println!("Nonce successfully saved to {}", out_path),
                        Err(e) => eprintln!("Error writing to {}: {}", out_path, e),
                    }
                }
            }
        },
    }
}

async fn deal_evidence_commands(command: &EvidenceCommands, config: Config) {
    match command {
        EvidenceCommands::Get { nonce_type, user_nonce, content, attester_data, out } => {
            // Load plugins
            println!("Starting to load plugins");
            load_plugins(&config)
                .map_err(|e| AgentError::PluginLoadError(format!("Failed to load plugins: {}", e)))
                .unwrap();
            println!("Plugins loaded successfully");
            let attester_type = get_attester_types(config);

            let nonce: Option<Nonce> = match content {
                None => None,
                Some(content) => {
                    let nonce = get_content(&Some(content.to_string()));
                    if nonce.is_none() {
                        eprintln!("Unable to obtain nonce");
                        return;
                    }
                    let nonce: Nonce = serde_json::from_str(&nonce.unwrap()).unwrap();
                    Some(nonce)
                },
            };
            let evidence_request = GetEvidenceRequest {
                attester_types: Option::from(attester_type),
                nonce_type: Option::from(nonce_type.to_string()),
                user_nonce: user_nonce.clone(),
                nonce,
                attester_data: attester_data.clone(),
            };
            match EvidenceManager::get_evidence(&evidence_request) {
                Ok(evidence) => {
                    let evidence_json =
                        serde_json::to_string_pretty(&evidence).expect("Failed to serialize evidence to JSON");

                    let out_path = out.to_string();
                    if let Err(e) = fs::create_dir_all(Path::new(&out_path).parent().unwrap()) {
                        eprintln!("Warning: Failed to create directories for {}: {}", out_path, e);
                        return;
                    }
                    match fs::write(&out_path, &evidence_json) {
                        Ok(_) => println!("Evidence successfully saved to {}", out_path),
                        Err(e) => eprintln!("Error writing to {}: {}", out_path, e),
                    }
                },
                Err(error) => eprintln!("Get Evidence failed: {}", error),
            }
        },
    }
}

async fn deal_token_commands(
    command: &TokenCommands,
    server_url: String,
    client: Client,
    user: &String,
    apikey: &String,
) {
    let url = format!("{}/token/verify", &server_url);
    match command {
        TokenCommands::Verify { file, token } => {
            let mut token_list: Vec<String> = Vec::new();
            if let Some(file) = file {
                let token_string = fs::read_to_string(file).unwrap();
                token_list = serde_json::from_str::<Vec<TokenResponse>>(&token_string)
                    .unwrap()
                    .into_iter()
                    .map(|item| item.token)
                    .collect();
            }
            if let Some(token) = token {
                token_list = token.iter().map(|token| token.to_string()).collect();
            }
            for token in token_list {
                let request_body = json!({
                    "token": token,
                });
                println!("verify token {}", &token);
                let response = client
                    .post(&url)
                    .header(USER_ID, HeaderValue::from_str(user).unwrap())
                    .header(API_KEY, HeaderValue::from_str(apikey).unwrap())
                    .json(&request_body)
                    .send()
                    .await
                    .unwrap();
                println!("status: {}", response.status());
                println!("body: {}", response.text().await.unwrap());
            }
        },
    }
}

fn get_config_path() -> String {
    if CONFIG_PATH.exists() {
        CONFIG_PATH.to_string_lossy().into_owned()
    } else {
        RPM_CONFIG_PATH.to_string()
    }
}

async fn register_apikey_commands(
    command: &RegisterCommands,
    server_url: String,
    client: Client,
    user_config: &String,
    apikey_config: &String,
) {
    let url = format!("{}/register", &server_url);
    let write;
    let mut user_req = String::new();
    let mut apikey_req = String::new();
    match command {
        RegisterCommands::New { nowrite } => {
            write = !*nowrite;
        },
        RegisterCommands::Refresh { user, apikey, nowrite } => {
            (user_req, apikey_req) = match (user, apikey) {
                (Some(user), Some(apikey)) => (user.to_string(), apikey.to_string()),
                (None, None) => (user_config.to_string(), apikey_config.to_string()),
                (_, _) => {
                    eprintln!("Error: user or apikey is missing");
                    std::process::exit(1);
                },
            };
            write = !*nowrite;
        },
    }
    let response = client
        .get(&url)
        .header(USER_ID, HeaderValue::from_str(&user_req).unwrap())
        .header(API_KEY, HeaderValue::from_str(&apikey_req).unwrap())
        .send()
        .await
        .unwrap();
    let status_code = response.status();
    let data = response.text().await.unwrap();
    println!("status: {}", status_code);
    println!("body: {}", data);
    if status_code != StatusCode::OK {
        eprintln!("Error: request failed");
        std::process::exit(1);
    }
    let response_data: serde_json::Value = serde_json::from_str(data.as_str()).unwrap();
    if write {
        let apikey = response_data.get("API-Key").unwrap().as_str().unwrap();
        let uid = response_data.get("User-Id").unwrap().as_str().unwrap();
        let config_path = get_config_path();
        println!("{}", &config_path);
        let mut file = File::open(&config_path).unwrap();
        let mut contents = String::new();
        file.read_to_string(&mut contents).unwrap();
        let mut config: serde_yaml::Value = serde_yaml::from_str(&contents).unwrap();
        if let serde_yaml::Value::Mapping(ref mut agent_map) = config["agent"] {
            agent_map
                .insert(serde_yaml::Value::String("user_id".to_string()), serde_yaml::Value::String(uid.to_string()));
            agent_map
                .insert(serde_yaml::Value::String("apikey".to_string()), serde_yaml::Value::String(apikey.to_string()));
        }
        let mut file = File::create(&config_path).unwrap();
        let updated_yaml = serde_yaml::to_string(&config).unwrap();
        file.write_all(updated_yaml.as_bytes()).unwrap();
    }
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    ConfigManager::new(&get_config_path()).unwrap();
    let config: Config = AGENT_CONFIG.get_instance().unwrap().clone();
    let server_url = if cli.server_url.is_empty() {
        config.clone().server.server_url + SERVICE_URL_PREFIX
    } else {
        cli.server_url + SERVICE_URL_PREFIX
    };
    let tls = config.clone().server.tls.unwrap();
    let cert_path = if cli.cert_path.is_empty() { tls.cert_path } else { cli.cert_path };
    let ca_path = if cli.ca_path.is_empty() { tls.ca_path } else { cli.ca_path };

    let mut user_id = cli.user.clone();
    user_id = if user_id.is_empty() { config.agent.user_id.clone().unwrap_or("".to_string()) } else { user_id };
    let mut apikey = cli.apikey.clone();
    apikey = if apikey.is_empty() { config.agent.apikey.clone().unwrap_or("".to_string()) } else { apikey };

    // Create client
    let client: Client = if server_url.starts_with("https://") {
        // 1. Load server CA certificate (to verify server identity)
        let server_ca_cert = fs::read(Path::new(&ca_path)).unwrap();
        let server_ca_cert = Certificate::from_pem(&server_ca_cert).unwrap();

        // 2. Load client certificate and private key (for server to verify client)
        let client_cert_and_key = fs::read(Path::new(&cert_path)).unwrap(); // Contains certificate and private key
        let client_identity = Identity::from_pem(&client_cert_and_key).unwrap();

        // 3. Create client with mutual authentication support
        Client::builder()
            .add_root_certificate(server_ca_cert) // Verify server certificate
            .identity(client_identity) // Provide client certificate
            .danger_accept_invalid_certs(false) // Strict certificate verification
            .build()
            .unwrap()
    } else {
        Client::builder().build().unwrap()
    };
    match &cli.group {
        CommandGroup::Policy { command } => {
            deal_policy_commands(command, server_url, client, &user_id, &apikey).await;
        },
        CommandGroup::Certificate { command } => {
            deal_certificate_commands(command, server_url, client, &user_id, &apikey).await;
        },
        CommandGroup::Baseline { command } => {
            deal_baseline_commands(command, server_url, client, &user_id, &apikey).await;
        },
        CommandGroup::Nonce { command } => {
            deal_nonce_commands(command, server_url, client, &user_id, config, &apikey).await;
        },
        CommandGroup::Evidence { command } => {
            deal_evidence_commands(command, config).await;
        },
        CommandGroup::Attest { message, file, out } => {
            let url = format!("{}/attest", &server_url);
            let evidence_data = fs::read_to_string(file).unwrap();
            let mut request_body: Value = serde_json::from_str(&evidence_data).unwrap();
            if let Value::Object(ref mut map) = request_body {
                map.insert("message".to_string(), json!(message));
            }
            // Send POST request
            let response = client
                .post(url)
                .header(USER_ID, HeaderValue::from_str(&user_id).unwrap())
                .header(API_KEY, HeaderValue::from_str(&apikey).unwrap())
                .json(&request_body)
                .send()
                .await
                .unwrap();
            let status = response.status();
            println!("status: {}", status);
            let text = &response.text().await.unwrap();
            if status != StatusCode::OK || out.is_none() {
                println!("body: {}", text);
            }
            if out.is_some() && status == StatusCode::OK {
                let response: Value = serde_json::from_str(text).unwrap();
                let nonce_json =
                    serde_json::to_string_pretty(&response.get("tokens")).expect("Failed to serialize tokens to JSON");
                let out_path = match out {
                    Some(path) => path,
                    None => {
                        eprintln!("Output path is Token, skipping file write");
                        return;
                    },
                };
                if let Err(e) = fs::create_dir_all(Path::new(&out_path).parent().unwrap()) {
                    eprintln!("Warning: Failed to create directories for {}: {}", out_path, e);
                    return;
                }
                match fs::write(&out_path, &nonce_json) {
                    Ok(_) => println!("Token successfully saved to {}", out_path),
                    Err(e) => eprintln!("Error writing to {}: {}", out_path, e),
                }
            }
        },
        CommandGroup::Token { command } => {
            deal_token_commands(command, server_url, client, &user_id, &apikey).await;
        },
        CommandGroup::Register { command } => {
            register_apikey_commands(command, server_url, client, &user_id, &apikey).await;
        },
    }
}
