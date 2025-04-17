use std::collections::HashMap;
use crate::key_manager::base_key_manager::{PrivateKey};
use crate::key_manager::openbao::openbao_command::OpenBaoManager;
use crate::key_manager::secret_manager_factory::SecretManagerType::OpenBao;
use crate::models::cipher_models::PutCipherReq;
use crate::utils::errors::AppError;

pub struct SecretManagerFactory;

pub trait SecretManager {
    fn get_all_secret(&self) -> Result<HashMap<String, Vec<PrivateKey>>, AppError>;
    fn import_secret(&self, cipher: &PutCipherReq) -> Result<String, AppError>;
    fn init_system(&self) -> Result<(), AppError>;
}

#[derive(Debug)]
pub enum SecretManagerType {
    OpenBao,
}

impl SecretManagerFactory {
    pub fn create_manager(manager_type: SecretManagerType) -> Box<dyn SecretManager> {
        match manager_type {
            OpenBao => {
                Box::new(OpenBaoManager::default())
            }
        }
    }
}