use std::collections::HashMap;

use common_log::error;

use crate::constants::VERIFIER_DEVELOPER;
use crate::entities::attest_request::Measurement;
use crate::entities::token::ear_token::{EarAttesterResult, EarSubmodResult, EarToken, EarTokenVerifierId, EarTrustworthinessVector};
use crate::entities::token::eat_token::{EatAttesterResult, EatToken};
use crate::entities::token::token_trait::{AttesterResult, Token, TokenType};
use crate::entities::token::PolicyInfo;


impl Token for EatToken {
    fn create_evidence_response(
        &mut self,
        verify_results: Vec<bool>,
        raw_evidence: Option<serde_json::Value>,
        policy_info: Vec<PolicyInfo>,
    ) -> AttesterResult {
        let attestation_status = if policy_info.is_empty() {
            "unknown"
        } else if verify_results.iter().all(|&x| x) {
            "pass"
        } else {
            "fail"
        };

        for policy in &policy_info {
            if policy.policy_matched {
                self.matched_policy.push(policy.appraisal_policy_id.clone());
            } else {
                self.unmatched_policy.push(policy.appraisal_policy_id.clone());
            }
        }
        
        let processed_evidence = match &raw_evidence {
            Some(evidence) => {
                evidence.get("annotated_evidence").cloned()
            },
            None => None,
        };

        AttesterResult::Eat(EatAttesterResult {
            attestation_status: attestation_status.to_string(),
            raw_evidence: processed_evidence,
            policy_info,
        })
    }

    fn create_attestation_response(
        &self,
        evidence_token_responses: &HashMap<String, AttesterResult>,
        nonce_type: &str,
        nonce: &Option<String>,
        measurement: &Measurement,
    ) -> TokenType {
        let mut eat_evidence_responses = HashMap::new();
        for (key, value) in evidence_token_responses {
            if let AttesterResult::Eat(eat_result) = value {
                eat_evidence_responses.insert(key.clone(), eat_result.clone());
            }
        }

        TokenType::Eat(EatToken {
            eat_nonce: match nonce_type {
                "verifier" | "user" => match serde_json::to_value(nonce) {
                    Ok(value) => Some(value),
                    Err(e) => {
                        error!("Failed to serialize user nonce: {}", e);
                        None
                    },
                },
                _ => None,
            },
            nonce_type: nonce_type.to_string(),
            attester_data: measurement.attester_data.clone(),
            results: eat_evidence_responses,
            intuse: Some("Generic".to_string()),
            ueid: Some(measurement.node_id.clone()),
            matched_policy: self.matched_policy.clone(),
            unmatched_policy: self.unmatched_policy.clone(),
        })
    }
}

impl Token for EarToken {
    fn create_evidence_response(
        &mut self,
        verify_results: Vec<bool>,
        raw_evidence: Option<serde_json::Value>,
        policy_info: Vec<PolicyInfo>,
    ) -> AttesterResult {
        let appraisal_policy_id =
            policy_info.first().map(|policy| policy.appraisal_policy_id.clone());

        let ear_status = if policy_info.is_empty() {
            "none"
        } else if verify_results.iter().all(|&x| x) {
            "affirming"
        } else {
            "contarindicated"
        };

        let (ear_trustworthiness_vector, ear_gta_annotated_evidence) = match &raw_evidence {
            Some(evidence) => {
                let mut trustworthiness_vector = EarTrustworthinessVector { hardware: None, executables: None };
                
                if let Some(hardware_value) = evidence.get("ear_trustworthiness_vector").and_then(|v| v.get("hardware")) {
                    if let Some(hardware) = hardware_value.as_i64() {
                        trustworthiness_vector.hardware = Some(hardware as i32);
                    }
                }
                
                if let Some(executables_value) = evidence.get("ear_trustworthiness_vector").and_then(|v| v.get("executables")) {
                    if let Some(executables) = executables_value.as_i64() {
                        trustworthiness_vector.executables = Some(executables as i32);
                    }
                }
                
                let annotated_evidence = evidence.get("annotated_evidence").cloned();
                
                (Some(vec![trustworthiness_vector]), annotated_evidence)
            }
            None => {
                (None, None)
            }
        };

        for policy in &policy_info {
            if policy.policy_matched {
                self.matched_policy.push(policy.appraisal_policy_id.clone());
            } else {
                self.unmatched_policy.push(policy.appraisal_policy_id.clone());
            }
        }

        AttesterResult::Ear(EarAttesterResult {
            ear_status: ear_status.to_string(),
            ear_trustworthiness_vector,
            ear_gta_annotated_evidence,
            ear_appraisal_policy_id: appraisal_policy_id,
        })
    }

    fn create_attestation_response(
        &self,
        evidence_token_responses: &HashMap<String, AttesterResult>,
        _nonce_type: &str,
        _nonce: &Option<String>,
        measurement: &Measurement,
    ) -> TokenType {
        let mut ear_submods = Vec::new();
        let mut ear_attester_results = HashMap::new();
        
        for (key, value) in evidence_token_responses {
            if let AttesterResult::Ear(ear_result) = value {
                ear_attester_results.insert(key.clone(), ear_result.clone());
            }
        }
        
        if !ear_attester_results.is_empty() {
            ear_submods.push(EarSubmodResult {
                ear_attester_results,
            });
        }

        TokenType::Ear(EarToken {
            ear_verifier_id: EarTokenVerifierId {
                developer: VERIFIER_DEVELOPER.to_string(),
                version: "v1.0.0".to_string(),
            },
            matched_policy: self.matched_policy.clone(),
            unmatched_policy: self.unmatched_policy.clone(),
            ueid: Some(measurement.node_id.clone()),
            ear_raw_evidence: None,
            submods: ear_submods,
        })
    }
}
