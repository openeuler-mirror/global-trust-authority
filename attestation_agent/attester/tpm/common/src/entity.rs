use serde::{Serialize, Deserialize};

// evidence structure
#[derive(Debug, Serialize, Deserialize)]
pub struct Evidence {
    // No prefix and suffix, only the base64 content
    pub ak_cert: String,
    pub quote: Quote,
    pub pcrs: Pcrs,
    pub logs: Vec<Log>,
}

// quote structure
#[derive(Debug, Serialize, Deserialize)]
pub struct Quote {
    pub quote_data: String,
    pub signature: String,
}

// pcrs structure
#[derive(Debug, Serialize, Deserialize)]
pub struct Pcrs { 
    pub hash_alg: String,      // default value is sha256
    pub pcr_values: Vec<PcrValue>,
}

// pcr value structure
#[derive(Debug, Serialize, Deserialize)]
pub struct PcrValue {
    pub pcr_index: i32,
    pub pcr_value: String,
}

// log structure
#[derive(Debug, Serialize, Deserialize)]
pub struct Log {
    pub log_type: String,       // example value: TcgEventLog, ImaLog
    pub log_data: String,
}

