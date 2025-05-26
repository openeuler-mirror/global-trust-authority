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

use clap::Subcommand;
use crate::entities::{CertType, ContentType, DeleteCertType, DeleteType, NonceType, PolicyDeleteType};

#[derive(Subcommand)]
pub enum CertificateCommands {
    /// Insert certificate and revoked certificate
    Set {
        /// Certificate name, default the file name
        #[clap(short, long)]
        name: Option<String>,

        /// Certificate description
        #[clap(short, long)]
        description: Option<String>,

        /// Certificate type
        #[clap(long, required = true, value_enum, num_args = 1.., value_delimiter = ' ')]
        cert_type: Vec<CertType>,

        /// Certificate content, starting with @ indicates the file path
        #[clap(long, allow_hyphen_values = true)]
        content: Option<String>,

        /// Revoked certificate file address, cert-type must be crl
        #[clap(short, long, num_args = 1.., value_delimiter = ' ')]
        revoke_certificate_file: Option<Vec<String>>,

        /// Is default certificate, default is' No '
        #[clap(short, long)]
        is_default: bool,
    },

    /// Delete certificate
    Delete {
        /// Delete type
        #[clap(short, long, required = true, value_enum)]
        delete_type: DeleteType,

        /// Certificate id list
        #[clap(short, long, num_args = 1.., value_delimiter = ' ')]
        ids: Option<Vec<String>>,

        /// Certificate type
        #[clap(short, long, value_enum)]
        cert_type: Option<DeleteCertType>,
    },

    /// Update certificate information
    Update {
        /// Certificate id
        #[clap(long, required = true)]
        id: String,

        /// Certificate name
        #[clap(short, long)]
        name: Option<String>,

        /// Certificate description
        #[clap(short, long)]
        description: Option<String>,

        /// Certificate type
        #[clap(short, long, value_enum, num_args = 1.., value_delimiter = ' ')]
        cert_type: Option<Vec<CertType>>,

        /// Is default certificate
        #[clap(short, long)]
        is_default: Option<bool>,
    },

    /// Query certificate information and revocation status
    Get {
        /// Certificate type
        #[clap(short, long, value_enum)]
        cert_type: Option<DeleteCertType>,

        /// Certificate id list
        #[clap(short, long, num_args = 1.., value_delimiter = ' ')]
        ids: Option<Vec<String>>,
    },
}

#[derive(Subcommand)]
pub enum PolicyCommands {
    /// Insert policy
    Set {
        /// Policy name, default the file name
        #[clap(short, long)]
        name: Option<String>,

        /// Policy description
        #[clap(short, long)]
        description: Option<String>,

        /// Applicable types of challenge plugins: tpm_ima/tpm_boot
        #[clap(short, long, num_args = 1.., value_delimiter = ' ')]
        attester_type: Vec<String>,

        /// Content type
        #[clap(long, required = true, value_enum)]
        content_type: ContentType,

        /// Policy content, starting with @ indicates the file path
        #[clap(long, required = true)]
        content: String,

        /// Is default policy, default is' No '
        #[clap(short, long)]
        is_default: bool,
    },
    /// Delete policy
    Delete {
        /// Delete type
        #[clap(short, long, required = true, value_enum)]
        delete_type: PolicyDeleteType,

        /// Policy id list
        #[clap(short, long, num_args = 1.., value_delimiter = ' ')]
        ids: Option<Vec<String>>,

        /// Applicable types of challenge plugins: tpm_ima/tpm_boot
        #[clap(short, long)]
        attester_type: Option<String>,
    },
    /// Update policy information
    Update {
        /// Policy id
        #[clap(long, required = true)]
        id: String,

        /// Policy name
        #[clap(short, long)]
        name: Option<String>,

        /// Policy description
        #[clap(short, long)]
        description: Option<String>,

        /// Applicable types of challenge plugins: tpm_ima/tpm_boot
        #[clap(short, long, num_args = 1.., value_delimiter = ' ')]
        attester_type: Option<Vec<String>>,

        /// Content type
        #[clap(long, required = true, value_enum)]
        content_type: Option<ContentType>,

        /// Policy content, starting with @ indicates the file path
        #[clap(long)]
        content: Option<String>,

        /// Is default policy, default is' No '
        #[clap(short, long)]
        is_default: Option<bool>,
    },
    /// Query policy information
    Get {
        /// Applicable types of challenge plugins: tpm_ima/tpm_boot
        #[clap(short, long)]
        attester_type: Option<String>,

        /// Policy id list
        #[clap(short, long, num_args = 1.., value_delimiter = ' ')]
        ids: Option<Vec<String>>,
    },
}

#[derive(Subcommand)]
pub enum BaselineCommands {
    /// Insert baseline
    Set {
        /// Baseline name, default the file name
        #[clap(short, long)]
        name: Option<String>,

        /// Baseline description
        #[clap(short, long)]
        description: Option<String>,

        /// Applicable types of challenge plugins: tpm_ima
        #[clap(short, long, default_value = "tpm_ima")]
        attester_type: String,

        /// Baseline content, starting with @ indicates the file path
        #[clap(short, long, required = true)]
        content: String,

        /// Is default baseline, default is' No '
        #[clap(short, long)]
        is_default: bool,
    },
    /// Delete baseline
    Delete {
        /// Delete type
        #[clap(short, long, required = true, value_enum)]
        delete_type: DeleteType,

        /// Baseline id list
        #[clap(short, long, num_args = 1.., value_delimiter = ' ')]
        ids: Option<Vec<String>>,

        /// Applicable types of challenge plugins: tpm_ima
        #[clap(short, long)]
        attester_type: Option<String>,
    },
    /// Update baseline information
    Update {
        /// Baseline id
        #[clap(long, required = true)]
        id: String,

        /// Baseline name
        #[clap(short, long)]
        name: Option<String>,

        /// Baseline description
        #[clap(short, long)]
        description: Option<String>,

        /// Applicable types of challenge plugins: tpm_ima
        #[clap(short, long)]
        attester_type: Option<String>,

        /// Baseline content, starting with @ indicates the file path
        #[clap(short, long)]
        content: Option<String>,

        /// Is default baseline, default is' No '
        #[clap(short, long)]
        is_default: Option<bool>,
    },
    /// Query baseline information
    Get {
        /// Applicable types of challenge plugins: tpm_ima
        #[clap(short, long)]
        attester_type: Option<String>,

        /// Baseline id list
        #[clap(short, long, num_args = 1.., value_delimiter = ' ')]
        ids: Option<Vec<String>>,
    },
}

#[derive(Subcommand)]
pub enum NonceCommands {
    /// Get nonce
    Get {
        /// Output file address
        #[clap(short, long)]
        out: Option<String>,
    },
}

#[derive(Subcommand)]
pub enum EvidenceCommands {
    /// Get evidence
    Get {
        /// Nonce type
        #[clap(short, long, required = true, value_enum)]
        nonce_type: NonceType,

        /// Fill in when nonce-type is user
        #[clap(short, long)]
        user_nonce: Option<String>,

        /// Nonce info, starting with @ indicates the file path
        #[clap(short, long)]
        content: Option<String>,

        /// Output file address
        #[clap(short, long, required = true)]
        out: String,

        /// User data, reserved fields
        #[clap(short, long)]
        attester_data: Option<String>,
    },
}

#[derive(Subcommand)]
pub enum TokenCommands {
    /// Verify token
    Verify {
        /// Token file address
        #[clap(short, long)]
        file: Option<String>,

        /// Token list
        #[clap(short, long, num_args = 1.., value_delimiter = ' ')]
        token: Option<Vec<String>>,
    },
}