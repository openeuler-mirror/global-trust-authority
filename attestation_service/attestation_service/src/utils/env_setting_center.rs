use std::env;
use actix_web::HttpResponse;
use env_config_parse::find_file;

pub async fn default_not_found_page() -> HttpResponse {
    HttpResponse::NotFound().body("Default Custom 404 Page")
}

pub fn load_env()  {
    dotenv::dotenv().ok();
    #[cfg(debug_assertions)]
    {
        dotenv::dotenv().ok().map(|_| std::env::vars().for_each(|(k, _)| std::env::remove_var(&k)));
        let env_file = find_file(".env.dev")
            .map(|file| file.to_str().unwrap().to_string()).unwrap_or("./.env.dev".to_string());
        dotenv::from_filename(env_file).expect("Failed to load .env.dev");
    }
}

pub fn get_address() -> String {
    get_env_by_key("ATTESTATION_ADDRESS".to_string())
}

pub fn get_https_address() -> String {
    get_env_by_key("HTTPS_ADDRESS".to_string())
}

pub fn get_key_path() -> String {
    get_env_by_key("KEY_PATH".to_string())
}

pub fn get_cert_path() -> String {
    get_env_by_key("CERT_PATH".to_string())
}

pub fn get_env_by_key(key: String) -> String {
    let key_clone = key.clone();
    env::var(key).expect(&format!("{} must be set", key_clone))
}

pub fn get_env_value_or_default<T>(key: &str, default: T) -> T
where
    T: std::str::FromStr,
{
    env::var(key)
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(default)
}