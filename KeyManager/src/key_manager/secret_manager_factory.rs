use crate::key_manager::base_key_manager::PrivateKeyVec;
use crate::key_manager::openbao::openbao_command::OpenBaoManager;
use crate::key_manager::secret_manager_factory::SecretManagerType::OpenBao;
use crate::models::cipher_models::CreateCipherReq;
use crate::utils::response::AppError;

pub struct SecretManagerFactory;

pub trait SecretManager {
    fn get_all_secret(&self) -> Result<PrivateKeyVec, i16>;
    fn import_secret(&self, cipher: &CreateCipherReq) -> Result<String, AppError>;
}

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