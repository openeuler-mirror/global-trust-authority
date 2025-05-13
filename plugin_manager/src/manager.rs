/// Plugin manager implementation

use std::collections::HashMap;
use std::sync::{Arc, OnceLock, RwLock};
use std::sync::atomic::{AtomicBool, Ordering};
use libloading::{Library, Symbol};

use log::{error, info};

use crate::traits::{PluginBase, PluginManagerInstance, ServicePlugin, AgentPlugin};
use crate::host_functions::{HostFunctions, ServiceHostFunctions, AgentHostFunctions};

/// Plugin storage structure
pub struct PluginEntry {
    pub(crate) _lib: Library, // Keep the library loaded
}

/// Generic plugin creation function type that takes a specific host function type
pub type CreatePluginFn<T, H> = fn(&H, &str) -> Option<Box<T>>;

/// Generic plugin manager that can work with any plugin type and host function type
pub struct PluginManager<T: PluginBase + ?Sized, H: HostFunctions> {
    // Store plugins with a single Arc layer for shared ownership
    plugins: RwLock<HashMap<String, (Arc<T>, PluginEntry)>>,
    // Track initialization state
    initialized: AtomicBool,
    // Phantom data to track the host function type
    _phantom: std::marker::PhantomData<H>,
}

impl<T: PluginBase + ?Sized + 'static, H: HostFunctions> PluginManager<T, H> {
    /// Create a new PluginManager
    fn new() -> Self {
        Self {
            plugins: RwLock::new(HashMap::new()),
            initialized: AtomicBool::new(false),
            _phantom: std::marker::PhantomData,
        }
    }

    /// Register a plugin with this manager
    fn register_plugin(&self, name: String, plugin: Box<T>, lib: Library) {
        let mut plugins = self.plugins.write().unwrap();
        let entry = PluginEntry {
            _lib: lib,
        };
        
        plugins.insert(name, (Arc::from(plugin), entry));
    }
    
    /// Get a plugin by name - returns an Arc to the plugin
    pub fn get_plugin(&self, name: &str) -> Option<Arc<T>> {
        let plugins = self.plugins.read().unwrap();
        let result = plugins.get(name).map(|(plugin, _)| plugin.clone());
        result
    }
    
    /// Get all plugin names
    pub fn get_plugin_types(&self) -> Vec<String> {
        let plugins = self.plugins.read().unwrap();
        let types = plugins.keys().cloned().collect();
        types
    }
    
    /// Check if the manager has been successfully initialized
    pub fn is_initialized(&self) -> bool {
        let initialized = self.initialized.load(Ordering::Relaxed);
        initialized
    }
    
        /// Helper function to load a single plugin
    /// Returns Ok(()) if successful, Err with error message otherwise
    unsafe fn load_plugin(&self, name: &str, path: &str, host_functions: &H) -> Result<(), String> {
        // Try to load the library
        let lib = Library::new(path)
            .map_err(|e| format!("Failed to load library {}: {}", path, e))?;
        
        // Try to get the create_plugin symbol
        let constructor = lib.get::<Symbol<CreatePluginFn<T, H>>>(b"create_plugin")
            .map_err(|e| format!("Failed to find create_plugin symbol: {}", e))?;
        
        // Try to create the plugin
        let plugin = constructor(host_functions, name)
            .ok_or_else(|| format!("Plugin creation failed for {}", name))?;
        
        if plugin.plugin_type() != name {
            return Err(format!("Plugin type mismatch for {}", name));
        }

        // Register the plugin
        self.register_plugin(name.to_string(), plugin, lib);
        Ok(())
    }

    /// Load plugins from a HashMap of plugin names and paths
    /// Returns true if all plugins were loaded successfully, false otherwise
    pub fn initialize(&self, plugin_paths: &HashMap<String, String>, host_functions: &H) -> bool {
        info!("Initializing plugin manager with {} plugins", plugin_paths.len());
        let mut all_successful = true;
        
        for (name, path) in plugin_paths {
            info!("Loading plugin '{}' from path: {}", name, path);
            let result = unsafe {
                self.load_plugin(name, path, host_functions)
            };
            if let Err(error) = result {
                error!("Error loading plugin {}: {}", name, error);
                all_successful = false;
            } else {
                info!("Successfully registered plugin: {}", name);
            }
        }
        
        // Set the initialization state based on the result
        self.initialized.store(all_successful, Ordering::Relaxed);
        if all_successful {
            info!("Plugin manager successfully initialized with all plugins");
        } else {
            error!("Plugin manager initialization completed with errors");
        }
        all_successful
    }
}

// Singleton implementations for different plugin types

// Implementation for ServicePlugin manager
impl PluginManagerInstance for PluginManager<dyn ServicePlugin, ServiceHostFunctions> {
    fn get_instance() -> &'static Self {
        static INSTANCE: OnceLock<PluginManager<dyn ServicePlugin, ServiceHostFunctions>> = OnceLock::new();
        INSTANCE.get_or_init(|| {
            PluginManager::new()
        })
    }
}

// Implementation for AgentPlugin manager
impl PluginManagerInstance for PluginManager<dyn AgentPlugin, AgentHostFunctions> {
    fn get_instance() -> &'static Self {
        static INSTANCE: OnceLock<PluginManager<dyn AgentPlugin, AgentHostFunctions>> = OnceLock::new();
        INSTANCE.get_or_init(|| {
            PluginManager::new()
        })
    }
}
