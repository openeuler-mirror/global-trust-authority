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

use tokio;
use serde_json::Value;
use plugin_manager::{ServiceHostFunctions, PluginError};
use tpm_common_verifier::{Evidence, PcrValues, GenerateEvidence, LogResult, EvidenceResult, Logs};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use async_trait::async_trait;

struct TestTpmBootPlugin {
    plugin_type: String,
    service_host_functions: ServiceHostFunctions,
}

impl TestTpmBootPlugin {
    pub fn new(
        plugin_type: String,
        service_host_functions: ServiceHostFunctions
    ) -> Self {
        Self { 
            plugin_type: plugin_type, 
            service_host_functions
        }
    }
}

#[async_trait]
impl GenerateEvidence for TestTpmBootPlugin {
    async fn generate_evidence(
        &self,
        _user_id: &str,
        _logs: Option<&Vec<Logs>>,
        pcr_values: &mut PcrValues
    ) -> Result<Value, PluginError> {
        let logs = vec![
            LogResult {
                log_type: "tpm_boot".to_string(),
                log_data: Some(serde_json::json!([
                    {
                        "event_number": 0,
                        "pcr_index": 1,
                        "event_type": "EV_NO_ACTION",
                        "digest": "0123456789abcdef0123456789abcdef01234567",
                        "event": {}
                    },
                    {
                        "event_number": 1, 
                        "pcr_index": 2,
                        "event_type": "EV_SEPARATOR",
                        "digest": "9876543210fedcba9876543210fedcba98765432",
                        "event": {}
                    }
                ])),
                log_status: "replay_success".to_string(),
                ref_value_match_status: "ignore".to_string(),
            }
        ];
        let evidence_result = EvidenceResult::new(logs, pcr_values.clone());
        let result = evidence_result.to_json_value();
        Ok(result)
    }

    fn get_host_functions(&self) -> &ServiceHostFunctions {
        &self.service_host_functions
    }

    fn get_plugin_type(&self) -> &str {
        &self.plugin_type
    }
}

#[tokio::test]
async fn test_evidence_verification() {
    // Create a plugin instance
    let plugin = TestTpmBootPlugin::new(
        "tpm_boot".to_string(),
        ServiceHostFunctions {
            validate_cert_chain: Box::new(|_, _, _| Box::pin(async { true })),
            get_unmatched_measurements: Box::new(|_, _, _| Box::pin(async { Ok(Vec::new()) })),
            query_configuration: |_| None
        }
    );
    let evidence_path = "tests/data/test_evidence.json";
    let evidence = std::fs::read_to_string(evidence_path)
        .expect("Failed to read test evidence file");
    let evidence_json: Value = serde_json::from_str(&evidence)
        .expect("Failed to parse JSON");

    let nonce =  "ljYr8vYNYrErFHGKeiL4vg==";
    let nonce_decoded = BASE64.decode(nonce).unwrap();

    let mut evidence_obj = Evidence::from_json_value(&evidence_json["evidence"])
        .expect("Failed to parse evidence");

    
    let evidence_result = evidence_obj.verify("test_user", Some("TestDevice"), Some(&nonce_decoded),
        &plugin).await;
    assert!(!evidence_result.is_ok());
}
