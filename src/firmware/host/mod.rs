// SPDX-License-Identifier: Apache-2.0
pub mod types;

use std::{
    fs::{File, OpenOptions},
    os::fd::{AsRawFd, RawFd},
};

use crate::error::*;
use types::*;

use FFI::ioctl::*;

use self::types::FFI::types::TryFromConfig;

///
/// This is a façade function to give public access to the FFI parse table
/// function.
///
pub fn parse_table(data: RawData) -> Result<Vec<CertTableEntry>, uuid::Error> {
    match data {
        RawData::Pointer(pointer) => unsafe {
            FFI::types::CertTableEntry::parse_table(pointer as *mut FFI::types::CertTableEntry)
        },
        RawData::Vector(vector) => unsafe {
            FFI::types::CertTableEntry::parse_table(
                vector.as_ptr() as *mut FFI::types::CertTableEntry
            )
        },
    }
}

/// A handle to the SEV platform.
pub struct Firmware(File);

impl Firmware {
    /// Create a handle to the SEV platform.
    pub fn open() -> std::io::Result<Firmware> {
        Ok(Firmware(
            OpenOptions::new().read(true).write(true).open("/dev/sev")?,
        ))
    }

    /// Query the SNP platform status.
    pub fn snp_platform_status(&mut self) -> Result<SnpPlatformStatus, Indeterminate<Error>> {
        let mut platform_status: SnpPlatformStatus = SnpPlatformStatus::default();
        SNP_PLATFORM_STATUS.ioctl(&mut self.0, &mut Command::from_mut(&mut platform_status))?;
        Ok(platform_status)
    }

    /// Fetch the SNP Extended Configuration.
    pub fn snp_get_ext_config(&mut self) -> Result<SnpExtConfig, UserApiError> {
        let mut raw_buf: Vec<u8> = vec![0; _4K_PAGE];
        let mut config: FFI::types::SnpGetExtConfig = FFI::types::SnpGetExtConfig {
            config_address: 0,
            certs_address: raw_buf.as_mut_ptr() as *mut CertTableEntry as u64,
            certs_len: _4K_PAGE as u32,
        };

        SNP_GET_EXT_CONFIG
            .ioctl(&mut self.0, &mut Command::from_mut(&mut config))
            .or_else(|err| {
                // If the error occurred because the buffer was to small, it will have changed
                // the buffer. If it has, we will attempt to resize it.
                if config.certs_len <= _4K_PAGE as u32 {
                    return Err(err);
                }

                raw_buf = vec![0; config.certs_len as usize];
                config.certs_address = raw_buf.as_ptr() as *const CertTableEntry as u64;
                SNP_GET_EXT_CONFIG.ioctl(&mut self.0, &mut Command::from_mut(&mut config))
            })?;

        config.try_into().map_err(|op: uuid::Error| op.into())
    }

    /// Set the SNP Extended Configuration.
    pub fn snp_set_ext_config(&mut self, new_config: SnpExtConfig) -> Result<bool, UserApiError> {
        let mut bytes: Vec<u8> = vec![];
        let mut new_ext_config: FFI::types::SnpSetExtConfig =
            FFI::types::SnpSetExtConfig::from_uapi(&new_config, &mut bytes)?;
        SNP_SET_EXT_CONFIG.ioctl(&mut self.0, &mut Command::from_mut(&mut new_ext_config))?;
        Ok(true)
    }
}

impl AsRawFd for Firmware {
    fn as_raw_fd(&self) -> RawFd {
        self.0.as_raw_fd()
    }
}
