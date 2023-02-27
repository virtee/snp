// SPDX-License-Identifier: Apache-2.0

use bitflags;
#[cfg(feature = "use-serde")]
use serde::{Deserialize, Serialize};

pub(crate) use crate::{error::SnpCertError, firmware::linux::guest::types::_4K_PAGE};

pub(crate) use crate::firmware::linux::host as FFI;

/// A representation of the type of data provided to [`parse_table`](crate::firmware::host::parse_table)
pub use crate::firmware::linux::host::types::RawData;

bitflags::bitflags! {
    /// The platform's status flags.
    #[derive(Default)]
    pub struct PlatformStatusFlags: u32 {
        /// If set, this platform is owned. Otherwise, it is self-owned.
        const OWNED           = 1 << 0;

        /// If set, encrypted state functionality is present.
        const ENCRYPTED_STATE = 1 << 8;
    }
}

/// Information about the SEV platform version.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
#[cfg_attr(feature = "use-serde", derive(Deserialize, Serialize))]
pub struct Version {
    /// The major version number.
    pub major: u8,

    /// The minor version number.
    pub minor: u8,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "use-serde", derive(Deserialize, Serialize))]
#[repr(C)]
/// Certificates which are accepted for [`CertTableEntry`](self::CertTableEntry)
pub enum SnpCertType {
    /// AMD Root Signing Key (ARK) certificate
    ARK,

    /// AMD SEV Signing Key (ASK) certificate
    ASK,

    /// Versioned Chip Endorsement Key (VCEK) certificate
    VCEK,

    /// Other (Specify GUID)
    OTHER(String),

    /// Empty or closing entry for the CertTable
    Empty,
}

impl From<&str> for SnpCertType {
    /// Create a certificate from the specified GUID. Any unexpected matches
    /// produce an [`SnpCertType::OTHER`](self::SnpCertType::OTHER) type from the guid provided.
    fn from(value: &str) -> Self {
        match value {
            "c0b406a4-a803-4952-9743-3fb6014cd0ae" => SnpCertType::ARK,
            "4ab7b379-bbac-4fe4-a02f-05aef327c782" => SnpCertType::ASK,
            "63da758d-e664-4564-adc5-f4b93be8accd" => SnpCertType::VCEK,
            "00000000-0000-0000-0000-000000000000" => SnpCertType::Empty,
            guid => SnpCertType::OTHER(guid.to_string()),
        }
    }
}

impl From<SnpCertType> for String {
    /// Find the String value of the GUID for a [`SnpCertType`](self::SnpCertType).
    fn from(value: SnpCertType) -> Self {
        match value {
            SnpCertType::ARK => "c0b406a4-a803-4952-9743-3fb6014cd0ae".to_string(),
            SnpCertType::ASK => "4ab7b379-bbac-4fe4-a02f-05aef327c782".to_string(),
            SnpCertType::VCEK => "63da758d-e664-4564-adc5-f4b93be8accd".to_string(),
            SnpCertType::Empty => "00000000-0000-0000-0000-000000000000".to_string(),
            SnpCertType::OTHER(guid) => guid,
        }
    }
}

impl From<&SnpCertType> for String {
    /// Find the String value of the GUID for a [`SnpCertType`](self::SnpCertType).
    fn from(value: &SnpCertType) -> Self {
        match value {
            SnpCertType::ARK => "c0b406a4-a803-4952-9743-3fb6014cd0ae".to_string(),
            SnpCertType::ASK => "4ab7b379-bbac-4fe4-a02f-05aef327c782".to_string(),
            SnpCertType::VCEK => "63da758d-e664-4564-adc5-f4b93be8accd".to_string(),
            SnpCertType::Empty => "00000000-0000-0000-0000-000000000000".to_string(),
            SnpCertType::OTHER(guid) => guid.to_string(),
        }
    }
}

impl ToString for SnpCertType {
    fn to_string(&self) -> String {
        self.into()
    }
}

impl TryFrom<SnpCertType> for uuid::Uuid {
    type Error = uuid::Error;

    fn try_from(value: SnpCertType) -> Result<Self, Self::Error> {
        match value {
            SnpCertType::ARK => uuid::Uuid::parse_str(&SnpCertType::ARK.to_string()),
            SnpCertType::ASK => uuid::Uuid::parse_str(&SnpCertType::ASK.to_string()),
            SnpCertType::VCEK => uuid::Uuid::parse_str(&SnpCertType::VCEK.to_string()),
            SnpCertType::Empty => uuid::Uuid::parse_str(&SnpCertType::Empty.to_string()),
            SnpCertType::OTHER(guid) => uuid::Uuid::parse_str(&guid),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "use-serde", derive(Deserialize, Serialize))]
#[repr(C)]
/// An entry with information regarding a specific certificate.
pub struct CertTableEntry {
    /// A Specificy certificate type.
    pub cert_type: SnpCertType,

    /// The raw data of the certificate.
    pub data: Vec<u8>,
}

impl CertTableEntry {
    /// Façade for retreiving the GUID for the Entry.
    pub fn guid_string(&self) -> String {
        self.cert_type.clone().into()
    }

    /// Get an immutable reference to the data stored in the entry.
    pub fn data(&self) -> &[u8] {
        self.data.as_slice()
    }

    /// Generates a certificate from the str GUID and data provided.
    pub fn from_guid(guid: &str, data: Vec<u8>) -> Self {
        Self {
            cert_type: guid.into(),
            data,
        }
    }

    /// Generates a certificate from the SnpCertType and data provided.
    pub fn new(cert_type: SnpCertType, data: Vec<u8>) -> Self {
        Self { cert_type, data }
    }
}

/// Information regarding the SEV-SNP platform's TCB version.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct SnpTcbStatus {
    /// Installed TCB version.
    pub platform_version: TcbVersion,

    /// Reported TCB version.
    pub reported_version: TcbVersion,
}

/// A description of the SEV-SNP platform's build information.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
#[cfg_attr(feature = "use-serde", derive(Deserialize, Serialize))]
pub struct SnpBuild {
    /// The version information.
    pub version: Version,

    /// The build ID.
    pub build: u32,
}

/// The platform state.
///
/// The underlying SEV-SNP platform behaves like a state machine and can
/// only perform certain actions while it is in certain states.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum State {
    /// The platform is uninitialized.
    Uninitialized,

    /// The platform is initialized, but not currently managing any
    /// guests.
    Initialized,

    /// The platform is initialized and is overseeing execution
    /// of encrypted guests.
    Working,
}

impl Default for State {
    fn default() -> Self {
        Self::Uninitialized
    }
}

/// Query the SEV-SNP platform status.
///
/// (Chapter 8.3; Table 38)
#[derive(Default)]
#[repr(C)]
pub struct SnpPlatformStatus {
    /// The firmware API version (major.minor)
    pub version: Version,

    /// The platform state.
    pub state: u8,

    /// IsRmpInitiailzied
    pub is_rmp_init: u8,

    /// The platform build ID.
    pub build_id: u32,

    /// MaskChipId
    pub mask_chip_id: u32,

    /// The number of valid guests maintained by the SEV-SNP firmware.
    pub guest_count: u32,

    /// Installed TCB version.
    pub platform_tcb_version: TcbVersion,

    /// Reported TCB version.
    pub reported_tcb_version: TcbVersion,
}

/// Rust-friendly instance of the SNP Extended Configuration.
/// It may be used either to fetch or set the configuration.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SnpExtConfig {
    /// SET:
    ///     Address of the SnpConfig or 0 when reported_tcb does not need
    ///     to be updated.
    ///
    /// GET:
    ///     Address of the SnpConfig or 0 when reported_tcb should not be
    ///     fetched.
    pub config: Option<SnpConfig>,

    /// SET:
    ///     Address of extended guest request certificate chain or None when
    ///     previous certificate should be removed on SNP_SET_EXT_CONFIG.
    ///
    /// GET:
    ///     Address of extended guest request certificate chain or None when
    ///     certificate should not be fetched.
    pub certs: Option<Vec<CertTableEntry>>,

    /// SET:
    ///     Length of the certificates.
    ///
    /// GET:
    ///     Length of the buffer which will hold the fetched certificates.
    pub certs_len: u32,
}

/// Used to round certificate buffers to 4K page alignment.
fn round_to_whole_pages(size: usize) -> usize {
    match size % _4K_PAGE {
        0 => size,
        rem => size + (_4K_PAGE - rem),
    }
}

impl SnpExtConfig {
    /// Used to update the PSP with the cerificates provided.
    pub fn update_certs_only(certificates: Vec<CertTableEntry>) -> Result<Self, SnpCertError> {
        let certs_length: usize = certificates.iter().map(|entry| entry.data().len()).sum();
        let certs_len: u32 = round_to_whole_pages(certs_length) as u32;

        Ok(Self {
            config: None,
            certs: Some(certificates),
            certs_len,
        })
    }
}

impl TryFrom<FFI::types::SnpGetExtConfig> for SnpExtConfig {
    type Error = uuid::Error;

    fn try_from(value: FFI::types::SnpGetExtConfig) -> Result<Self, Self::Error> {
        let mut config: Option<SnpConfig> = None;
        let mut certs: Option<Vec<CertTableEntry>> = None;
        if let Some(config_ref) = unsafe { (value.config_address as *mut SnpConfig).as_mut() } {
            config = Some(*config_ref);
        }

        if let Some(certificates) =
            unsafe { (value.certs_address as *mut FFI::types::CertTableEntry).as_mut() }
        {
            certs = Some(unsafe { FFI::types::CertTableEntry::parse_table(certificates)? })
        }

        Ok(Self {
            config,
            certs,
            certs_len: value.certs_len,
        })
    }
}

impl TryFrom<FFI::types::SnpSetExtConfig> for SnpExtConfig {
    type Error = uuid::Error;

    fn try_from(value: FFI::types::SnpSetExtConfig) -> Result<Self, Self::Error> {
        let mut config: Option<SnpConfig> = None;
        let mut certs: Option<Vec<CertTableEntry>> = None;
        if let Some(config_ref) = unsafe { (value.config_address as *mut SnpConfig).as_mut() } {
            config = Some(*config_ref);
        }

        if let Some(certificates) =
            unsafe { (value.certs_address as *mut FFI::types::CertTableEntry).as_mut() }
        {
            certs = Some(unsafe { FFI::types::CertTableEntry::parse_table(certificates)? })
        }

        Ok(Self {
            config,
            certs,
            certs_len: value.certs_len,
        })
    }
}

/// Sets the system wide configuration values for SNP.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(C, packed)]
pub struct SnpConfig {
    /// The TCB_VERSION to report in guest attestation reports.
    pub reported_tcb: TcbVersion,

    /// Indicates that the CHIP_ID field in the attestationr eport will always
    /// be zero.
    pub mask_chip_id: u32,

    /// Reserved. Must be zero.
    reserved: [u8; 52],
}

impl Default for SnpConfig {
    fn default() -> Self {
        Self {
            reported_tcb: Default::default(),
            mask_chip_id: Default::default(),
            reserved: [0; 52],
        }
    }
}

impl SnpConfig {
    /// Used to create a new SnpConfig
    pub fn new(reported_tcb: TcbVersion, mask_chip_id: u32) -> Self {
        Self {
            reported_tcb,
            mask_chip_id,
            reserved: [0; 52],
        }
    }
}

impl From<FFI::types::SnpConfig> for SnpConfig {
    fn from(value: FFI::types::SnpConfig) -> Self {
        Self {
            reported_tcb: value.reported_tcb.into(),
            mask_chip_id: value.mask_chip_id,
            reserved: value.reserved,
        }
    }
}

/// TcbVersion represents the version of the firmware.
///
/// (Chapter 2.2; Table 3)
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct TcbVersion {
    /// Current bootloader version.
    /// SVN of PSP bootloader.
    pub bootloader: u8,
    /// Current PSP OS version.
    /// SVN of PSP operating system.
    pub tee: u8,
    _reserved: [u8; 4],
    /// Version of the SNP firmware.
    /// Security Version Number (SVN) of SNP firmware.
    pub snp: u8,
    /// Lowest current patch level of all the cores.
    pub microcode: u8,
}

impl TcbVersion {
    /// Creates a new isntance of a TcbVersion
    pub fn new(bootloader: u8, tee: u8, snp: u8, microcode: u8) -> Self {
        Self {
            bootloader,
            tee,
            snp,
            microcode,
            _reserved: Default::default(),
        }
    }
}

impl From<FFI::types::TcbVersion> for TcbVersion {
    fn from(value: FFI::types::TcbVersion) -> Self {
        Self {
            bootloader: value.bootloader,
            tee: value.tee,
            _reserved: value.reserved,
            snp: value.snp,
            microcode: value.microcode,
        }
    }
}
