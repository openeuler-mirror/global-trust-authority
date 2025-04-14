pub mod config {
    pub const SECRET_PATH: &'static str = "key_manager";
    pub const TOKEN_ARRAY: [&'static str; 3] = ["FSK", "NSK", "TSK"];
    pub const KEY_MANAGER_PORT: &'static str = "KEY_MANAGER_PORT";
    pub const KEY_MANAGER_TLS: &'static str = "KEY_MANAGER_TLS";
    pub const KEY_MANAGER_CERT_PATH: &'static str = "KEY_MANAGER_CERT_PATH";
    pub const KEY_MANAGER_KEY_PATH: &'static str = "KEY_MANAGER_KEY_PATH";
    pub const KEY_MANAGER_LOG_LEVEL: &'static str = "KEY_MANAGER_LOG_LEVEL";
    pub const KEY_MANAGER_LOG_PATH: &'static str = "KEY_MANAGER_LOG_PATH";
    pub const KEY_MANAGER_ROOT_TOKEN: &'static str = "KEY_MANAGER_ROOT_TOKEN";
}