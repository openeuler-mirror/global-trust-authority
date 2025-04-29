/// Plugin interface library for dynamic plugin loading

mod host_functions;
mod traits;
mod manager;
pub mod init_plugin;

// Re-export all public items explicitly
// From interface
pub use traits::PluginBase;
pub use traits::ServicePlugin;
pub use traits::AgentPlugin;
pub use traits::PluginManagerInstance;
pub use traits::PluginError;

// From host_functions.rs
pub use host_functions::HostFunctions;
pub use host_functions::ServiceHostFunctions;
pub use host_functions::AgentHostFunctions;
pub use host_functions::ValidateCertChainFn;
pub use host_functions::GetUnmatchedMeasurementsFn;
pub use host_functions::QueryConfigurationFn;

// From manager.rs
pub use manager::PluginManager;
pub use manager::PluginEntry;
pub use manager::CreatePluginFn;

// Re-export serde_json only for tests and test plugins
#[cfg(any(test, feature = "test-plugins"))]
pub use serde_json;
