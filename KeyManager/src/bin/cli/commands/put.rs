use KeyManager::key_manager::secret_manager_factory::SecretManagerFactory;
use KeyManager::key_manager::secret_manager_factory::SecretManagerType::OpenBao;
use KeyManager::models::cipher_models::PutCipherReq;
use KeyManager::utils::response::AppError;
use clap::Args;
use validator::Validate;

#[derive(Args, Debug)]
pub struct PutArgs {
    /// Key name
    #[arg(long = "key_name", required = true)]
    pub key_name: String,

    /// Encoding mode
    #[arg(long = "encoding", value_parser = ["PEM"], default_value = "PEM")]
    pub encoding: String,

    /// Encryption algorithm
    #[arg(long = "algorithm", required = true, value_parser = ["RSA3072", "SM2", "EC"])]
    pub algorithm: String,

    /// Private key content, cannot be used with '--file_path'
    #[arg(long = "private_key", conflicts_with = "file_path")]
    pub private_key: Option<String>,

    /// Private key file path, cannot be used with '--private_key'
    #[arg(long = "file_path", conflicts_with = "private_key")]
    pub file_path: Option<String>,
}

pub fn handle_put(args: PutArgs) -> Result<(), AppError> {
    let put_cipher = PutCipherReq {
        key_name: args.key_name,
        encoding: args.encoding,
        algorithm: args.algorithm,
        private_key: args.private_key.unwrap_or_default(),
        file_path: args.file_path.unwrap_or_default(),
    };
    put_cipher.validate()?;
    SecretManagerFactory::create_manager(OpenBao).import_secret(&put_cipher)?;
    log::info!("handle put successfully");
    Ok(())
}
