use plugin_manager::{PluginBase, ServicePlugin, ServiceHostFunctions, ValidateCertChainFn, GetUnmatchedMeasurementsFn, QueryConfigurationFn, serde_json, PluginError};
use serde_json::Value;
use async_trait::async_trait;

/// A simple test service plugin for testing the plugin manager
pub struct TestServicePlugin<'a> {
    plugin_type: String,
    validate_cert_chain: &'a ValidateCertChainFn,
    get_unmatched_measurements: &'a GetUnmatchedMeasurementsFn,
    query_configuration: &'a QueryConfigurationFn,
}

impl<'a> TestServicePlugin<'a> {
    fn new(
        plugin_type: String,
        validate_cert_chain: &'a ValidateCertChainFn,
        get_unmatched_measurements: &'a GetUnmatchedMeasurementsFn,
        query_configuration: &'a QueryConfigurationFn,
    ) -> Self {
        Self {
            plugin_type,
            validate_cert_chain,
            get_unmatched_measurements,
            query_configuration,
        }
    }
}

impl<'a> PluginBase for TestServicePlugin<'a> {
    fn plugin_type(&self) -> &str {
        self.plugin_type.as_str()
    }
}

#[async_trait]
impl<'a> ServicePlugin for TestServicePlugin<'a> {
    fn get_sample_output(&self) -> Value {
        serde_json::json!({
            "cert_verification_result": true,
            "unmatched_value": ["test"],
            "config": "test" 
        })
    }
    
    async fn verify_evidence(&self, _user_id: &str, _node_id: Option<&str>, _evidence: &serde_json::Value, _nonce: Option<&[u8]>) -> Result<serde_json::Value, PluginError> {
        let cert_verification_result = (self.validate_cert_chain)("test_cert_type", "test_user_id", b"test").await;
        let unmatched_value = match (self.get_unmatched_measurements)(&vec![String::from("test")], "test", "test").await {
            Ok(values) => values,
            Err(err) => return Err(PluginError::InternalError(format!("Failed to get unmatched measurements: {}", err))),
        };
        let config = (self.query_configuration)(String::from("test"));
        Ok(serde_json::json!({
            "cert_verification_result": cert_verification_result,
            "unmatched_value": unmatched_value,
            "config": config
        }))
    }
}

#[no_mangle]
pub fn create_plugin<'a>(host_functions: &'a ServiceHostFunctions, plugin_type: &str) -> Option<Box<dyn ServicePlugin + 'a>> {
    // Extract the functions from the host functions struct
    let validate_cert_chain = &host_functions.validate_cert_chain;
    let get_unmatched_measurements = &host_functions.get_unmatched_measurements;
    let query_configuration = &host_functions.query_configuration;
    
    // Create a new instance with the host functions
    Some(Box::new(TestServicePlugin::new(String::from(plugin_type), validate_cert_chain, get_unmatched_measurements, query_configuration)))
}
