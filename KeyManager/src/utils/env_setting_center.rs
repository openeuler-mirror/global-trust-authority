use std::env;

pub fn load_env()  {
    dotenv::dotenv().ok();
}


pub fn get_port() -> u16 {
    match env::var("KEY_MANAGER_PORT") {
        Ok(data) => data.parse::<u16>().unwrap_or_else(|_| {
            log::warn!("WARNING: Invalid KEY_MANAGER_PORT value '{}', defaulting to 'true'", data);
            8080
        }),
        Err(_) => {
            log::warn!("Missing KEY_MANAGER_PORT environment variable");
            8080
        }
    }
}

pub fn get_tls() -> bool {
    match env::var("KEY_MANAGER_TLS") {
        Ok(data) => data.parse().unwrap_or_else(|_| {
            log::warn!("WARNING: Invalid KEY_MANAGER_TLS value '{}', defaulting to 'true'", data);
            true
        }),
        Err(_) => {
            log::warn!("Missing KEY_MANAGER_TLS environment variable");
            true
        }
    }
}

pub fn get_cert() -> String {
    env::var("KEY_MANAGER_CERT_PATH").expect("Missing KEY_MANAGER_CERT_PATH environment variable")
}

pub fn get_key() -> String {
    env::var("KEY_MANAGER_KEY_PATH").expect("Missing KEY_MANAGER_KEY_PATH environment variable")
}