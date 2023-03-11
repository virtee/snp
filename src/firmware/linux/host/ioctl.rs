// SPDX-License-Identifier: Apache-2.0
use iocuddle::*;
use std::marker::PhantomData;

use super::types::*;
use crate::firmware::host::types::SnpPlatformStatus;
use crate::impl_const_id;

// These enum ordinal values are defined in the Linux kernel
// source code: include/uapi/linux/psp-sev.h
impl_const_id! {
    pub Id => u32;
    SnpPlatformStatus = 0x9,
    SnpSetExtConfig = 0xA,
    SnpGetExtConfig = 0xB,
}

const SEV: Group = Group::new(b'S');

/// Return information about the current status and capabilities of the SEV-SNP platform.
pub const SNP_PLATFORM_STATUS: Ioctl<WriteRead, &Command<SnpPlatformStatus>> =
    unsafe { SEV.write_read(0) };

/// Set the SNP Extended Configuration Settings.
/// C IOCTL calls -> sev_ioctl_snp_set_config
pub const SNP_SET_EXT_CONFIG: Ioctl<WriteRead, &Command<SnpSetExtConfig>> =
    unsafe { SEV.write_read(0) };

/// Get the SNP Extended Configuration Settings.
pub const SNP_GET_EXT_CONFIG: Ioctl<WriteRead, &Command<SnpGetExtConfig>> =
    unsafe { SEV.write_read(0) };

/// The Rust-flavored, FFI-friendly version of `struct sev_issue_cmd` which is
/// used to pass arguments to the SEV ioctl implementation.
///
/// This struct is defined in the Linux kernel: include/uapi/linux/psp-sev.h
#[repr(C, packed)]
pub struct Command<'a, T: Id> {
    pub code: u32,
    pub data: u64,
    pub error: u32,
    _phantom: PhantomData<&'a T>,
}

impl<'a, T: Id> Command<'a, T> {
    /// Create an SEV command with the expectation that the host platform/kernel will write to
    /// the caller's address space either to the data held in the `Command.subcmd` field or some
    /// other region specified by the `Command.subcmd` field.
    pub fn from_mut(subcmd: &'a mut T) -> Self {
        Command {
            code: T::ID,
            data: subcmd as *mut T as u64,
            error: 0,
            _phantom: PhantomData,
        }
    }
}
