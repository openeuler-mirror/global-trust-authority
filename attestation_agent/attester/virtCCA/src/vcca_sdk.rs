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

use plugin_manager::PluginError;

#[allow(non_camel_case_types)]
pub type wchar_t = ::std::os::raw::c_int;

#[repr(C)]
#[derive(Debug, Copy, Clone)]
#[allow(non_camel_case_types)]
pub struct tsi_ctx {
    pub fd: wchar_t,
}

#[cfg(target_arch = "aarch64")]
#[link(name = "vccaattestation")]
extern "C" {
    pub fn tsi_new_ctx() -> *mut tsi_ctx;
}

#[cfg(target_arch = "aarch64")]
extern "C" {
    pub fn tsi_free_ctx(ctx: *mut tsi_ctx);
}

#[cfg(target_arch = "aarch64")]
extern "C" {
    #[allow(dead_code)]
    pub fn get_version(ctx: *mut tsi_ctx, major: *mut wchar_t, minor: *mut wchar_t) -> wchar_t;
}

#[cfg(target_arch = "aarch64")]
extern "C" {
    pub fn get_attestation_token(
        ctx: *mut tsi_ctx,
        challenge: *mut ::std::os::raw::c_uchar,
        challenge_len: usize,
        token: *mut ::std::os::raw::c_uchar,
        token_len: *mut usize,
    ) -> wchar_t;
}

#[cfg(target_arch = "aarch64")]
extern "C" {
    pub fn get_dev_cert(
        ctx: *mut tsi_ctx,
        dev_cert: *mut ::std::os::raw::c_uchar,
        dev_cert_len: *mut usize,
    ) -> wchar_t;
}

/// Represents the VCCA SDK for interacting with attestation services.
pub struct VccaSdk {
    #[allow(dead_code)]
    ctx: *mut tsi_ctx,
}

#[cfg(target_arch = "aarch64")]
impl VccaSdk {
    /// Creates a new instance of `VccaSdk`.
    ///
    /// # Returns
    /// A `Result` containing the `VccaSdk` or a `PluginError` if creation fails.
    pub fn new() -> Result<Self, PluginError> {
        let ctx = unsafe { tsi_new_ctx() };
        if ctx.is_null() {
            return Err(PluginError::InternalError("Failed to create tsi context".to_string()));
        }
        Ok(VccaSdk { ctx })
    }

    /// Retrieves the attestation token using the provided challenge.
    ///
    /// # Parameters
    /// - `challenge`: A byte slice containing the challenge data.
    ///
    /// # Returns
    /// A `Result` containing the token as `Vec<u8>` or a `PluginError`.
    pub fn get_attestation_token(&self, challenge: &[u8]) -> Result<Vec<u8>, PluginError> {
        let p_challenge = challenge.as_ptr() as *mut ::std::os::raw::c_uchar;
        let challenge_len = challenge.len() as usize;

        let mut token = Vec::new();
        token.resize(4096, b'\0');
        let p_token = token.as_mut_ptr() as *mut ::std::os::raw::c_uchar;
        let mut token_len = token.len();
        let p_token_len = &mut token_len as *mut usize;

        let ret = unsafe { get_attestation_token(self.ctx, p_challenge, challenge_len, p_token, p_token_len) };
        if ret != 0 {
            return Err(PluginError::InternalError(format!("virtcca get attestation token failed {}", ret)));
        }
        unsafe { token.set_len(token_len) };

        Ok(token)
    }

    /// Retrieves the device certificate.
    ///
    /// # Returns
    /// A `Result` containing the certificate as `Vec<u8>` or a `PluginError`.
    pub fn get_dev_cert(&self) -> Result<Vec<u8>, PluginError> {
        let mut dev_cert = Vec::new();
        dev_cert.resize(4096, b'\0');
        let p_dev_cert = dev_cert.as_mut_ptr() as *mut ::std::os::raw::c_uchar;
        let mut dev_cert_len = dev_cert.len();
        let p_dev_cert_len = &mut dev_cert_len as *mut usize;

        let ret = unsafe { get_dev_cert(self.ctx, p_dev_cert, p_dev_cert_len) };
        if ret != 0 {
            return Err(PluginError::InternalError(format!("get dev cert failed {}", ret)));
        }
        unsafe { dev_cert.set_len(dev_cert_len) };

        Ok(dev_cert)
    }
}

#[cfg(target_arch = "aarch64")]
impl Drop for VccaSdk {
    fn drop(&mut self) {
        unsafe {
            tsi_free_ctx(self.ctx);
        }
    }
}

#[cfg(not(target_arch = "aarch64"))]
impl VccaSdk {
    /// Attempts to create a new instance of `VccaSdk` (unsupported on non-ARM64).
    ///
    /// # Returns
    /// Always returns a `PluginError` indicating unsupported architecture.
    pub fn new() -> Result<Self, PluginError> {
        Err(PluginError::InternalError("VirtCCA attestation only supported on ARM64 architecture".to_string()))
    }

    /// Attempts to retrieve the attestation token (unsupported on non-ARM64).
    ///
    /// # Parameters
    /// - `_challenge`: Ignored challenge data.
    ///
    /// # Returns
    /// Always returns a `PluginError` indicating unsupported architecture.
    pub fn get_attestation_token(&self, _challenge: &[u8]) -> Result<Vec<u8>, PluginError> {
        Err(PluginError::InternalError("VirtCCA attestation only supported on ARM64 architecture".to_string()))
    }

    /// Attempts to retrieve the device certificate (unsupported on non-ARM64).
    ///
    /// # Returns
    /// Always returns a `PluginError` indicating unsupported architecture.
    pub fn get_dev_cert(&self) -> Result<Vec<u8>, PluginError> {
        Err(PluginError::InternalError("VirtCCA attestation only supported on ARM64 architecture".to_string()))
    }
}
