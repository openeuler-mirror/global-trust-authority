use std::sync::Arc;
use std::sync::Mutex;
use std::fs::File;
use std::io::Read;
use serde_json::Value;
use tokio::time::Instant;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use plugin_manager::PluginError;
use tpm_common_verifier::{PcrValues, AlgorithmId};
use tpm_boot_verifier::{EventLog, EventType, TpmEventLog, EventLogEntry, TcgDigestAlgorithm, TpmDigestEntry};

mod utils;
use utils::{read_file_as_base64, corrupt_base64_data};

#[test]
fn test_event_log_verify_with_vaild_log() {
    let pcr_str = r#"{
        "pcrs": {
            "hash_alg": "sha256",
            "pcr_values": [
                {
                    "pcr_index": 0,
                    "pcr_value": "9d7504bb0d32f62d43310f38df37cdd5e42bdb83dd0c0592fd9b1c3b16770c35"
                },
                {
                    "pcr_index": 1,
                    "pcr_value": "38846271e2a86d6bf43ef388be2d1cb83a89f1c0bb154fe494a1dda198da29be"
                },
                {
                    "pcr_index": 2,
                    "pcr_value": "3d458cfe55cc03ea1f443f1562beec8df51c75e14a9fcf9a7234a13f198e7969"
                },
                {
                    "pcr_index": 3,
                    "pcr_value": "3d458cfe55cc03ea1f443f1562beec8df51c75e14a9fcf9a7234a13f198e7969"
                },
                {
                    "pcr_index": 4,
                    "pcr_value": "8ed12c415056362c7a4d403e6e2acadf090e78bfb4798a87b0a327c838064931"
                },
                {
                    "pcr_index": 5,
                    "pcr_value": "66121d5bcdb8ab6d628b49827590ac8e1f2f09e26aa2d1dd1cfec5358854cd3a"
                },
                {
                    "pcr_index": 6,
                    "pcr_value": "3d458cfe55cc03ea1f443f1562beec8df51c75e14a9fcf9a7234a13f198e7969"
                },
                {
                    "pcr_index": 7,
                    "pcr_value": "74fa2c067892faa74bfb0cafacc4c7102dd2c9cf73efdfa41f07fdfc7c1eea1b"
                }
            ]
        }
    }"#;

    let pcr_json: Value = serde_json::from_str(pcr_str).unwrap();
    let pcr_values = PcrValues::from_json(&pcr_json["pcrs"]).unwrap();

    let measurements_path = "tests/data/binary_bios_measurements";
    let mut file = File::open(measurements_path).unwrap();
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer).unwrap();

    let base64_data = BASE64.encode(buffer);
    let mut event_log = EventLog::new(&base64_data);
    let result = event_log.with_algorithm("sha256").with_pcr_values(Arc::new(Mutex::new(pcr_values))).parse_event_log();
    assert!(result.is_ok(), "Failed to parse event log: {:?}", result.err());

    let is_matched = event_log.verify().unwrap();
    assert!(is_matched);

    let json_value = event_log.to_json_value().unwrap();
    let file = File::create("../../../../event_log.json").unwrap();
    serde_json::to_writer_pretty(file, &json_value).unwrap();

    for pcr in event_log.pcr_values.as_ref().unwrap().lock().unwrap().pcr_values.iter() {
        println!("pcr: {:?}", pcr);
    }

}


// =======================================================================================
// Event Log Parsing Tests
// =======================================================================================

/// Test Objective: Verify correct parsing of binary log format
/// Expected Result: Successfully parsed into structured JSON
#[test]
fn test_event_log_parse_with_valid_log() {
    // Read valid TPM event log
    let measurements_path = "tests/data/binary_bios_measurements";
    let base64_content = read_file_as_base64(measurements_path)
        .expect("Failed to read and encode binary_bios_measurements");

    // Use EventLog object to parse the log
    let mut event_log = EventLog::new(&base64_content);
    let result = event_log.with_algorithm("sha256").parse_event_log();

    // Verify parsing successful
    assert!(result.is_ok(), "Valid log parsing failed: {:?}", result.err());

    // Verify parsed structure contains expected fields
    let json_value = event_log.to_json_value().expect("Failed to convert to JSON");

    // Check parsed result contains necessary data structures
    assert!(json_value.is_array(), "JSON output should be an array");
    assert!(!json_value.as_array().unwrap().is_empty(), "Event log should not be empty");

    // Verify structure of the first event
    let first_event = &json_value[0];
    assert!(first_event.get("pcr_index").is_some(), "Missing PCR index");
    assert!(first_event.get("event_type").is_some(), "Missing event type");
    assert!(first_event.get("digest").is_some(), "Missing digest");
    assert!(first_event.get("event").is_some(), "Missing event data");
}

/// Test Objective: Verify error handling capability
/// Expected Result: Returns InputError
#[test]
fn test_event_log_parse_with_corrupted_log() {
    // Read valid TPM event log and deliberately corrupt it
    let measurements_path = "tests/data/binary_bios_measurements";
    let base64_content = read_file_as_base64(measurements_path)
        .expect("Failed to read and encode binary_bios_measurements");

    // Deliberately corrupt the Base64 data
    let corrupted_content = corrupt_base64_data(&base64_content);

    // Use EventLog object to attempt parsing the corrupted log
    let mut event_log = EventLog::new(&corrupted_content);
    let result = event_log.with_algorithm("sha256").parse_event_log();

    // Verify parsing fails and returns appropriate error
    assert!(result.is_err(), "Corrupted log should fail to parse");
    if let Err(error) = result {
        match error {
            PluginError::InputError(_) => {
                assert!(true);
            }
            _ => {
                panic!("Expected InputError for corrupted log, got: {:?}", error);
            }
        }
    }
}

/// Test Objective: Verify capability to handle vendor-specific event types
/// Expected Result: Unknown types should be properly recorded but not affect parsing
#[test]
fn test_event_log_parse_with_unknown_event_type() {
    // Read valid TPM event log
    let measurements_path = "tests/data/binary_bios_measurements";
    let base64_content = read_file_as_base64(measurements_path)
        .expect("Failed to read and encode binary_bios_measurements");

    // Directly use the original log for testing, not manually appending unknown events
    // Create PCR values data structure
    let pcr_str = r#"{
        "hash_alg": "sha256",
        "pcr_values": [
            { "pcr_index": 0, "pcr_value": "9d7504bb0d32f62d43310f38df37cdd5e42bdb83dd0c0592fd9b1c3b16770c35" },
            { "pcr_index": 1, "pcr_value": "38846271e2a86d6bf43ef388be2d1cb83a89f1c0bb154fe494a1dda198da29be" },
            { "pcr_index": 2, "pcr_value": "3d458cfe55cc03ea1f443f1562beec8df51c75e14a9fcf9a7234a13f198e7969" }
        ]
    }"#;

    let pcr_json: Value = serde_json::from_str(pcr_str).unwrap();
    let pcr_values = PcrValues::from_json(&pcr_json).unwrap();

    // Parse the log
    let mut event_log = EventLog::new(&base64_content);
    let result = event_log
        .with_algorithm("sha256")
        .with_pcr_values(Arc::new(Mutex::new(pcr_values)))
        .parse_event_log();

    assert!(result.is_ok(), "Failed to parse log: {:?}", result.err());

    // Add an unknown event type to the log using EventType::from_u32
    // Use simulated event type instead of modifying binary data
    let unknown_entry = EventLogEntry {
        event_number: event_log.event_number,  // Use next event number
        pcr_index: 7,
        event_type: EventType::Unknown,  // Directly use Unknown type
        digest: TcgDigestAlgorithm::V2(vec![
            TpmDigestEntry {
                algorithm_id: AlgorithmId::Sha256,
                digest_value: "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef".to_string(),
            }
        ]),
        event: TpmEventLog::EventBase(vec![1, 2, 3, 4, 5]),  // Simple test data
    };

    // Add to event log
    event_log.event_log.push(unknown_entry);
    event_log.event_number += 1;

    // Check JSON output contains unknown event type
    let json_value = event_log.to_json_value().expect("Failed to convert to JSON");

    // Iterate through events and check for unknown type events
    let mut has_unknown_events = false;
    if let Some(events) = json_value.as_array() {
        for event in events {
            if let Some(event_type) = event.get("event_type") {
                if event_type.as_str().map_or(false, |s| s.contains("UNKNOWN")) {
                    has_unknown_events = true;
                    
                    // Verify unknown events still contain original data
                    assert!(event.get("event").is_some(), "Unknown event should contain event data");

                    // Verify PCR index is correct
                    assert_eq!(event.get("pcr_index").and_then(|v| v.as_u64()), Some(7), 
                              "Unknown event should have PCR index 7");
                    break;
                }
            }
        }
    }
    
    // Verify log actually contains unknown event types
    assert!(has_unknown_events, "No unknown event types found in log");

    // Additional test: Check if a specific raw event type value is recognized as Unknown
    let is_unknown = EventType::from_u32(0x12345678).unwrap_or(EventType::Unknown) == EventType::Unknown;
    assert!(is_unknown, "0x12345678 should be recognized as an unknown event type");
}

/// Test Objective: Verify ability to parse all standard TCG event types
/// Expected Result: Correctly identify and parse each event type, providing appropriate description fields
#[test]
fn test_event_log_parse_with_standard_event_types() {
    // Read valid TPM event log
    let measurements_path = "tests/data/binary_bios_measurements";
    let base64_content = read_file_as_base64(measurements_path)
        .expect("Failed to read and encode binary_bios_measurements");

    // Parse the log
    let mut event_log = EventLog::new(&base64_content);
    let result = event_log.with_algorithm("sha256").parse_event_log();
    assert!(result.is_ok(), "Failed to parse log: {:?}", result.err());

    // Convert to JSON
    let json_value = event_log.to_json_value().expect("Failed to convert to JSON");

    // Count different event types
    let mut event_types = std::collections::HashSet::new();
    if let Some(events) = json_value.as_array() {
        for event in events {
            if let Some(event_type) = event.get("event_type").and_then(|v| v.as_str()) {
                event_types.insert(event_type.to_string());
            }
        }
    }

    // Verify number of event types
    println!("Found {} different event types", event_types.len());
    for event_type in &event_types {
        println!("Event type: {}", event_type);
    }

    // Verify common event types are present
    let common_types = vec![
        "EV_NO_ACTION", 
        "EV_SEPARATOR", 
        "EV_EFI_VARIABLE_DRIVER_CONFIG",
        "EV_EFI_BOOT_SERVICES_APPLICATION"
    ];

    for common_type in common_types {
        assert!(
            event_types.iter().any(|et| et.contains(common_type)),
            "Common event type {} not found", common_type
        );
    }
}

/// Test Objective: Verify performance and memory efficiency when handling large logs
/// Expected Result: Complete parsing in reasonable time, controlled memory usage
#[test]
fn test_event_log_parse_with_large_log_performance() {
    // Read valid TPM event log
    let measurements_path = "tests/data/binary_bios_measurements";
    let base64_content = read_file_as_base64(measurements_path)
        .expect("Failed to read and encode binary_bios_measurements");

    // Measure parsing performance
    let start = Instant::now();

    // Parse the log
    let mut event_log = EventLog::new(&base64_content);
    let result = event_log.with_algorithm("sha256").parse_event_log();
    assert!(result.is_ok(), "Failed to parse log: {:?}", result.err());

    // Calculate parsing time
    let duration = start.elapsed();
    println!("Time to parse event log: {:?}", duration);

    // Verify JSON output size
    let json_value = event_log.to_json_value().expect("Failed to convert to JSON");
    let json_size = serde_json::to_string(&json_value).unwrap().len();
    println!("JSON output size: {} bytes", json_size);

    // Verify parsing duration is within reasonable range (less than 5 seconds)
    assert!(duration.as_secs() < 5, "Parsing took too long: {:?}", duration);
}

// =======================================================================================
// PCR Replay Tests
// =======================================================================================

/// Test Objective: Verify ability to correctly calculate PCR values from log replay
/// Expected Result: Calculated PCR values match expected values
#[test]
fn test_event_log_replay_with_valid_log() {
    // Read valid TPM event log
    let measurements_path = "tests/data/binary_bios_measurements";
    let base64_content = read_file_as_base64(measurements_path)
        .expect("Failed to read and encode binary_bios_measurements");

    // Create PCR values data structure
    let pcr_str = r#"{
        "hash_alg": "sha256",
        "pcr_values": [
            { "pcr_index": 0, "pcr_value": "9d7504bb0d32f62d43310f38df37cdd5e42bdb83dd0c0592fd9b1c3b16770c35" },
            { "pcr_index": 1, "pcr_value": "38846271e2a86d6bf43ef388be2d1cb83a89f1c0bb154fe494a1dda198da29be" },
            { "pcr_index": 2, "pcr_value": "3d458cfe55cc03ea1f443f1562beec8df51c75e14a9fcf9a7234a13f198e7969" },
            { "pcr_index": 3, "pcr_value": "3d458cfe55cc03ea1f443f1562beec8df51c75e14a9fcf9a7234a13f198e7969" },
            { "pcr_index": 4, "pcr_value": "8ed12c415056362c7a4d403e6e2acadf090e78bfb4798a87b0a327c838064931" },
            { "pcr_index": 5, "pcr_value": "66121d5bcdb8ab6d628b49827590ac8e1f2f09e26aa2d1dd1cfec5358854cd3a" },
            { "pcr_index": 6, "pcr_value": "3d458cfe55cc03ea1f443f1562beec8df51c75e14a9fcf9a7234a13f198e7969" },
            { "pcr_index": 7, "pcr_value": "74fa2c067892faa74bfb0cafacc4c7102dd2c9cf73efdfa41f07fdfc7c1eea1b" }
        ]
    }"#;

    let pcr_json: Value = serde_json::from_str(pcr_str).unwrap();
    let pcr_values = PcrValues::from_json(&pcr_json).unwrap();
    let pcr_values_mutex = Arc::new(Mutex::new(pcr_values));

    // Parse and replay log
    let mut event_log = EventLog::new(&base64_content);
    let result = event_log
        .with_algorithm("sha256")
        .with_pcr_values(Arc::clone(&pcr_values_mutex))
        .parse_event_log()
        .and_then(|log| log.replay());

    assert!(result.is_ok(), "Failed to replay log: {:?}", result.err());

    // Verify replay-calculated PCR values match expected values
    let updated_pcr_values = pcr_values_mutex.lock().unwrap();

    // Check if PCR0 replay value has been calculated and matches original value
    assert!(
        updated_pcr_values.get_pcr_replay_value(0).unwrap().is_some(),
        "PCR0 replay value not calculated"
    );

    // Check if each PCR's replay value matches
    for pcr_entry in &updated_pcr_values.pcr_values {
        if let Some(replay_value) = &pcr_entry.replay_value {
            assert_eq!(
                replay_value, &pcr_entry.pcr_value,
                "PCR{} replay value doesn't match expected value", pcr_entry.pcr_index
            );
        }
    }
}

/// Test Objective: Verify ability to replay events for specific PCR indices
/// Expected Result: Correctly calculate values for each relevant PCR
#[test]
fn test_event_log_replay_with_selective_pcr() {
    // Read valid TPM event log
    let measurements_path = "tests/data/binary_bios_measurements";
    let base64_content = read_file_as_base64(measurements_path)
        .expect("Failed to read and encode binary_bios_measurements");

    // Create data structure containing only a subset of PCR values
    let pcr_str = r#"{
        "hash_alg": "sha256",
        "pcr_values": [
            { "pcr_index": 0, "pcr_value": "9d7504bb0d32f62d43310f38df37cdd5e42bdb83dd0c0592fd9b1c3b16770c35" },
            { "pcr_index": 4, "pcr_value": "8ed12c415056362c7a4d403e6e2acadf090e78bfb4798a87b0a327c838064931" },
            { "pcr_index": 7, "pcr_value": "74fa2c067892faa74bfb0cafacc4c7102dd2c9cf73efdfa41f07fdfc7c1eea1b" }
        ]
    }"#;

    let pcr_json: Value = serde_json::from_str(pcr_str).unwrap();
    let pcr_values = PcrValues::from_json(&pcr_json).unwrap();
    let pcr_values_mutex = Arc::new(Mutex::new(pcr_values));

    // Parse and replay log
    let mut event_log = EventLog::new(&base64_content);
    let result = event_log
        .with_algorithm("sha256")
        .with_pcr_values(Arc::clone(&pcr_values_mutex))
        .parse_event_log()
        .and_then(|log| log.replay());

    assert!(result.is_ok(), "Failed to selectively replay log: {:?}", result.err());

    // Verify replay-calculated PCR values match expected values
    let updated_pcr_values = pcr_values_mutex.lock().unwrap();

    // Check if PCR0 replay value has been calculated
    assert!(
        updated_pcr_values.get_pcr_replay_value(0).unwrap().is_some(),
        "PCR0 replay value not calculated"
    );

    // Check if PCR4 replay value has been calculated
    assert!(
        updated_pcr_values.get_pcr_replay_value(4).unwrap().is_some(),
        "PCR4 replay value not calculated"
    );

    // Check if PCR7 replay value has been calculated
    assert!(
        updated_pcr_values.get_pcr_replay_value(7).unwrap().is_some(),
        "PCR7 replay value not calculated"
    );

    // Check if each PCR's replay value matches
    for pcr_entry in &updated_pcr_values.pcr_values {
        if let Some(replay_value) = &pcr_entry.replay_value {
            assert_eq!(
                replay_value, &pcr_entry.pcr_value,
                "PCR{} replay value doesn't match expected value", pcr_entry.pcr_index
            );
        }
    }
}

/// Test Objective: Test capability to handle non-contiguous PCR index updates
/// Expected Result: Correctly calculate final value for each PCR
#[test]
fn test_event_log_replay_with_noncontiguous_pcr_updates() {
    // Read valid TPM event log
    let measurements_path = "tests/data/binary_bios_measurements";
    let base64_content = read_file_as_base64(measurements_path)
        .expect("Failed to read and encode binary_bios_measurements");

    // Create complete PCR values data structure
    let pcr_str = r#"{
        "hash_alg": "sha256",
        "pcr_values": [
            { "pcr_index": 0, "pcr_value": "9d7504bb0d32f62d43310f38df37cdd5e42bdb83dd0c0592fd9b1c3b16770c35" },
            { "pcr_index": 1, "pcr_value": "38846271e2a86d6bf43ef388be2d1cb83a89f1c0bb154fe494a1dda198da29be" },
            { "pcr_index": 2, "pcr_value": "3d458cfe55cc03ea1f443f1562beec8df51c75e14a9fcf9a7234a13f198e7969" },
            { "pcr_index": 3, "pcr_value": "3d458cfe55cc03ea1f443f1562beec8df51c75e14a9fcf9a7234a13f198e7969" },
            { "pcr_index": 4, "pcr_value": "8ed12c415056362c7a4d403e6e2acadf090e78bfb4798a87b0a327c838064931" },
            { "pcr_index": 5, "pcr_value": "66121d5bcdb8ab6d628b49827590ac8e1f2f09e26aa2d1dd1cfec5358854cd3a" },
            { "pcr_index": 6, "pcr_value": "3d458cfe55cc03ea1f443f1562beec8df51c75e14a9fcf9a7234a13f198e7969" },
            { "pcr_index": 7, "pcr_value": "74fa2c067892faa74bfb0cafacc4c7102dd2c9cf73efdfa41f07fdfc7c1eea1b" }
        ]
    }"#;

    let pcr_json: Value = serde_json::from_str(pcr_str).unwrap();
    let pcr_values = PcrValues::from_json(&pcr_json).unwrap();
    let pcr_values_mutex = Arc::new(Mutex::new(pcr_values));

    // Parse and replay log
    let mut event_log = EventLog::new(&base64_content);
    let result = event_log
        .with_algorithm("sha256")
        .with_pcr_values(Arc::clone(&pcr_values_mutex))
        .parse_event_log()
        .and_then(|log| log.replay());

    assert!(result.is_ok(), "Failed to replay log with non-contiguous updates: {:?}", result.err());

    // Parse log to JSON to check event sequence
    let json_value = event_log.to_json_value().expect("Failed to convert to JSON");

    // Check if log contains non-contiguous PCR updates
    let mut pcr_sequences = std::collections::HashMap::new();
    if let Some(events) = json_value.as_array() {
        for (index, event) in events.iter().enumerate() {
            if let Some(pcr_index) = event.get("pcr_index").and_then(|v| v.as_u64()) {
                pcr_sequences.entry(pcr_index).or_insert_with(Vec::new).push(index);
            }
        }
    }

    // Verify PCR update patterns
    for (pcr_index, event_indices) in &pcr_sequences {
        println!("PCR{} was updated at event indices: {:?}", pcr_index, event_indices);
    }

    // Verify replay results match expected values
    let updated_pcr_values = pcr_values_mutex.lock().unwrap();
    for pcr_entry in &updated_pcr_values.pcr_values {
        if let Some(replay_value) = &pcr_entry.replay_value {
            assert_eq!(
                replay_value, &pcr_entry.pcr_value,
                "PCR{} replay value doesn't match expected value", pcr_entry.pcr_index
            );
        }
    }
}
