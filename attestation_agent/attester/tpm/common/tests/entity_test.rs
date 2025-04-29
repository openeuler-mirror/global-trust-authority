use tpm_common_attester::Log;
use serde_json::{json, to_value, from_value};

#[test]
fn test_log_serialization() {
    // Create a Log instance
    let log = Log {
        log_type: "TcgEventLog".to_string(),
        log_data: "base64_encoded_data".to_string(),
    };
    
    // Serialize to JSON
    let json_value = to_value(&log).expect("Failed to serialize Log");
    
    // Verify JSON structure
    assert_eq!(json_value["log_type"], "TcgEventLog");
    assert_eq!(json_value["log_data"], "base64_encoded_data");
    
    // Deserialize from JSON
    let deserialized: Log = from_value(json_value).expect("Failed to deserialize Log");
    
    // Verify deserialized values
    assert_eq!(deserialized.log_type, "TcgEventLog");
    assert_eq!(deserialized.log_data, "base64_encoded_data");
}

#[test]
fn test_evidence_structure() {
    // Create a sample evidence JSON
    let evidence_json = json!({
        "ak_cert": "sample_ak_cert_data",
        "quote": {
            "quote_data": "sample_quote_data",
            "signature": "sample_signature"
        },
        "pcrs": {
            "hash_algo": "sha256",
            "pcr_values": [
                {
                    "pcr_index": 0,
                    "pcr_value": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                },
                {
                    "pcr_index": 1,
                    "pcr_value": "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
                }
            ]
        },
        "log": [
            {
                "log_type": "TcgEventLog",
                "log_data": "sample_log_data_1"
            },
            {
                "log_type": "ImaLog",
                "log_data": "sample_log_data_2"
            }
        ]
    });
    
    // Verify JSON structure
    assert!(evidence_json["ak_cert"].is_string());
    assert!(evidence_json["quote"].is_object());
    assert!(evidence_json["pcrs"].is_object());
    assert!(evidence_json["log"].is_array());
    
    // Verify quote structure
    assert!(evidence_json["quote"]["quote_data"].is_string());
    assert!(evidence_json["quote"]["signature"].is_string());
    
    // Verify PCRs structure
    assert_eq!(evidence_json["pcrs"]["hash_algo"], "sha256");
    assert!(evidence_json["pcrs"]["pcr_values"].is_array());
    assert_eq!(evidence_json["pcrs"]["pcr_values"].as_array().unwrap().len(), 2);
    
    // Verify log structure
    let logs = evidence_json["log"].as_array().unwrap();
    assert_eq!(logs.len(), 2);
    assert_eq!(logs[0]["log_type"], "TcgEventLog");
    assert_eq!(logs[1]["log_type"], "ImaLog");
}
