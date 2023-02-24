// SPDX-License-Identifier: Apache-2.0

use std::{
    fs::{File, OpenOptions},
    os::fd::{AsRawFd, RawFd},
};

pub(crate) mod ioctl;
pub(crate) mod macros;
pub(crate) mod types;

use ioctl::*;
use types::*;

use crate::firmware::host::types as UAPI;

use crate::error::*;

use super::guest::types::_4K_PAGE;

pub fn snp_platform_status() -> Result<UAPI::SnpPlatformStatus, Indeterminate<Error>> {
    let mut platform_status: UAPI::SnpPlatformStatus = UAPI::SnpPlatformStatus::default();
    let mut fw: Firmware = Firmware::open()?;
    fw.snp_platform_status(&mut platform_status)?;
    Ok(platform_status)
}

pub fn snp_get_ext_config() -> Result<UAPI::SnpExtConfig, UserApiError> {
    let mut raw_buf: Vec<u8> = vec![0; _4K_PAGE];
    let mut config: SnpGetExtConfig = SnpGetExtConfig {
        config_address: 0,
        certs_address: raw_buf.as_mut_ptr() as *mut CertTableEntry as u64,
        certs_len: _4K_PAGE as u32,
    };
    let mut fw: Firmware = Firmware::open()?;
    fw.snp_get_ext_config(&mut raw_buf, &mut config)?;
    Ok(config.try_into()?)
}

pub fn snp_set_ext_config(new_config: &UAPI::SnpExtConfig) -> Result<bool, UserApiError> {
    let mut bytes: Vec<u8> = vec![];
    let mut new_config: SnpSetExtConfig = SnpSetExtConfig::from_uapi(new_config, &mut bytes)?;
    let mut fw: Firmware = Firmware::open()?;
    fw.snp_set_ext_config(&mut new_config)?;
    Ok(true)
}

///
/// This is a façade function to give public access to the FFI parse table
/// function.
///
pub fn parse_table(data: RawData) -> Result<Vec<UAPI::CertTableEntry>, uuid::Error> {
    match data {
        RawData::Pointer(pointer) => unsafe {
            CertTableEntry::parse_table(pointer as *mut CertTableEntry)
        },
        RawData::Vector(vector) => {
            let mut copied_data = vector;
            unsafe { CertTableEntry::parse_table(copied_data.as_mut_ptr() as *mut CertTableEntry) }
        }
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
    pub fn snp_platform_status(
        &mut self,
        platform_status: &mut UAPI::SnpPlatformStatus,
    ) -> Result<(), Indeterminate<Error>> {
        SNP_PLATFORM_STATUS.ioctl(&mut self.0, &mut Command::from_mut(platform_status))?;
        Ok(())
    }

    /// Fetch the SNP Extended Configuration.
    pub fn snp_get_ext_config(
        &mut self,
        raw_buf: &mut Vec<u8>,
        config: &mut SnpGetExtConfig,
    ) -> Result<(), UserApiError> {
        if let Err(error) = SNP_GET_EXT_CONFIG.ioctl(&mut self.0, &mut Command::from_mut(config)) {
            // If the error occurred because the buffer was to small, it will have changed the
            // buffer. If it has, we will attempt to resize it.
            if config.certs_len > _4K_PAGE as u32 {
                *raw_buf = vec![0; config.certs_len as usize];
                config.certs_address = raw_buf.as_mut_ptr() as *mut CertTableEntry as u64;

                SNP_GET_EXT_CONFIG.ioctl(&mut self.0, &mut Command::from_mut(config))?;
            } else {
                return Err(error.into());
            }
        }

        Ok(())
    }

    /// Set the SNP Extended Configuration.
    pub fn snp_set_ext_config(
        &mut self,
        new_config: &mut SnpSetExtConfig,
    ) -> Result<(), UserApiError> {
        SNP_SET_EXT_CONFIG.ioctl(&mut self.0, &mut Command::from_mut(new_config))?;
        Ok(())
    }
}

impl AsRawFd for Firmware {
    fn as_raw_fd(&self) -> RawFd {
        self.0.as_raw_fd()
    }
}
