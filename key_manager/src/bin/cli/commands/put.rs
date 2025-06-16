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

use key_managerd::key_manager::secret_manager_factory::SecretManagerFactory;
use key_managerd::key_manager::secret_manager_factory::SecretManagerType::OpenBao;
use key_managerd::models::cipher_models::PutCipherReq;
use key_managerd::utils::errors::AppError;
use clap::Args;
use validator::Validate;

#[derive(Args, Debug)]
#[command(
    override_usage = "key_manager put --key_name <KEY_NAME> --algorithm <ALGORITHM> [--encoding <ENCODING>] [--private_key <PRIVATE_KEY>] [--key_file <KEY_FILE>]"
)]
pub struct PutArgs {
    /// Key name
    #[arg(short = 'n', long = "key_name", required = true, value_parser = ["FSK", "NSK", "TSK"], ignore_case = true)]
    pub key_name: String,

    /// Encoding mode
    #[arg(long, value_parser = ["pem"], ignore_case = true, default_value = "pem")]
    #[arg(verbatim_doc_comment)]
    pub encoding: String,

    /// Encryption algorithm
    #[arg(long, required = true, value_parser = ["rsa_3072"], ignore_case = true)]
    pub algorithm: String,

    /// Private key content, cannot be used with '--key_file'
    #[arg(long = "private_key", conflicts_with = "key_file")]
    pub private_key: Option<String>,

    /// Private key file path, cannot be used with '--private_key'
    #[arg(long = "key_file", conflicts_with = "private_key")]
    pub key_file: Option<String>,
}

/// Params:
///      args: param for bin
/// # Errors 
///     execute error
pub fn handle_put(args: PutArgs) -> Result<(), AppError> {
    let put_cipher = PutCipherReq {
        key_name: args.key_name.to_uppercase(),
        encoding: args.encoding.to_lowercase(),
        algorithm: args.algorithm.to_lowercase(),
        private_key: args.private_key.unwrap_or_default(),
        key_file: args.key_file.unwrap_or_default(),
    };
    put_cipher.validate()?;
    SecretManagerFactory::create_manager(OpenBao).import_secret(&put_cipher)?;
    log::info!("handle put successfully");
    Ok(())
}
