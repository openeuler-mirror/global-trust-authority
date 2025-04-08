pub mod config {
    pub const SECRET_PATH: &'static str = "key_manager";
    pub const FSK: &'static str = "FSK";
    pub const NSK: &'static str = "NSK";
    pub const TSK: &'static str = "TSK";
}

pub mod status_code {
    pub const OPENBAO_NOT_AVAILABLE: i16 = 10001;
    pub const OPENBAO_COMMAND_EXECUTE_ERROR: i16 = 10002;
    pub const OPENBAO_COMMAND_EXCEPTION: i16 = 10003;
    pub const OPENBAO_JSON_ERROR: i16 = 10004;
}
