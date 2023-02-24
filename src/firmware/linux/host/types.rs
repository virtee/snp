// SPDX-License-Identifier: Apache-2.0

use crate::firmware::host::types as UAPI;
use crate::{
    error::{SnpCertError, UserApiError},
    firmware::linux::guest::types::_4K_PAGE,
};

use uuid::Uuid;

pub enum RawData {
    /// A mutable pointer to an unsigned byte.
    Pointer(*mut u8),

    /// A vector of bytes.
    Vector(Vec<u8>),
}

impl From<*mut u8> for RawData {
    fn from(value: *mut u8) -> Self {
        Self::Pointer(value)
    }
}

impl <const SIZE: usize> From<[u8; SIZE]> for RawData {
    fn from(value: [u8; SIZE]) -> Self {
        Self::Vector(Vec::from(value))
    }
}

impl From<&[u8]> for RawData {
    fn from(value: &[u8]) -> Self {
        Self::Vector(value.into())
    }
}

impl From<Vec<u8>> for RawData {
    fn from(value: Vec<u8>) -> Self {
        Self::Vector(value)
    }
}

impl From<&Vec<u8>> for RawData {
    fn from(value: &Vec<u8>) -> Self {
        Self::Vector(value.to_vec())
    }
}

impl From<&mut Vec<u8>> for RawData {
    fn from(value: &mut Vec<u8>) -> Self {
        Self::Vector(value.to_vec())
    }
}


/// TcbVersion represents the version of the firmware.
///
/// (Chapter 2.2; Table 3)
#[repr(C)]
pub struct TcbVersion {
    /// Current bootloader version.
    /// SVN of PSP bootloader.
    pub bootloader: u8,
    /// Current PSP OS version.
    /// SVN of PSP operating system.
    pub tee: u8,
    pub reserved: [u8; 4],
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
            reserved: Default::default(),
            snp,
            microcode,
        }
    }
}

/// Sets the system wide configuration values for SNP.
#[repr(C, packed)]
pub struct SnpConfig {
    /// The TCB_VERSION to report in guest attestation reports.
    pub reported_tcb: TcbVersion,

    /// Indicates that the CHIP_ID field in the attestationr eport will always
    /// be zero.
    pub mask_chip_id: u32,

    /// Reserved. Must be zero.
    pub reserved: [u8; 52],
}

/// Structure used for interacting with the Linux Kernel.
///
/// The original C structure looks like this:
///
/// ```C
/// struct cert_table {
///    struct {
///       unsigned char guid[16];
///       uint32 offset;
///       uint32 length;
///    } cert_table_entry[];
/// };
/// ```
///
#[derive(Copy, Clone)]
#[repr(C)]
pub struct CertTableEntry {
    /// Sixteen character GUID.
    guid: [u8; 16],

    /// The starting location of the certificate blob.
    offset: u32,

    /// The number of bytes to read from the offset.
    length: u32,
}

impl CertTableEntry {
    /// Builds a Kernel formatted CertTable for sending the certificate content to the PSP.
    ///
    /// Users should pass the rust-friendly vector of [`UAPI::CertTableEntry`], and this function
    /// will handle adding the last entry and the structuring of the buffer sent to the hypervisor.
    ///
    /// The contiguous memory layout should look similar to this:
    ///
    /// ```text
    ///             |-> |------------------|    |-  CertTableEntry -|
    ///             |   | CertTableEntry_1 <<<--| - guid            |
    ///             |   | CertTableEntry_2 |    | - offset          |
    /// CertTable --|   | ...              |    | - length          |
    ///             |   | ...              |    |-------------------|
    ///             |   | ...              |
    ///             |-> | CertTableEntry_z | <-- last entry all zeroes
    /// offset (1)  --> | RawCertificate_1 |
    ///                 | ...              |
    ///                 | ...              |
    /// offset (2)  --> | RawCertificate_2 |
    ///                 | ...              |
    ///                 | ...              |
    /// offset (n)  --> | RawCertificate_n |
    ///                 |------------------|
    ///
    /// ```
    ///
    pub fn uapi_to_vec_bytes(
        table: &mut Vec<UAPI::CertTableEntry>,
    ) -> Result<Vec<u8>, SnpCertError> {
        // Create the vector to return for later.
        let mut bytes: Vec<u8> = vec![];

        // Find the location where the first certificate should begin.
        let mut offset: u32 = (std::mem::size_of::<CertTableEntry>() * (table.len() + 1)) as u32;

        // Create the buffer to store the table and certificates.
        let mut raw_certificates: Vec<u8> = vec![];

        for entry in table.iter() {
            let guid: Uuid = match Uuid::parse_str(&entry.guid_string()) {
                Ok(uuid) => uuid,
                Err(_) => return Err(SnpCertError::InvalidGUID),
            };

            // Append the guid to the byte array.
            bytes.extend_from_slice(guid.as_bytes());

            // Append the offset location to the byte array.
            bytes.extend_from_slice(&offset.to_ne_bytes());

            // Append the length to the byte array.
            bytes.extend_from_slice(&(entry.data.len() as u32).to_ne_bytes());

            // Copy the certificate data out until concatenating it later.
            raw_certificates.extend_from_slice(entry.data.as_slice());

            // Increment the offset
            offset += entry.data.len() as u32;
        }

        // Append the the empty entry to signify the end of the table.
        bytes.append(&mut vec![0u8; 24]);

        // Append the certificate bytes to the end of the table.
        bytes.append(&mut raw_certificates);

        Ok(bytes)
    }

    /// Parses the raw array of bytes into more human understandable information.
    ///
    /// The original C structure looks like this:
    ///
    /// ```C
    /// struct cert_table {
    ///    struct {
    ///       unsigned char guid[16];
    ///       uint32 offset;
    ///       uint32 length;
    ///    } cert_table_entry[];
    /// };
    /// ```
    ///
    pub unsafe fn parse_table(
        mut data: *mut CertTableEntry,
    ) -> Result<Vec<UAPI::CertTableEntry>, uuid::Error> {
        // Helpful Constance for parsing the data
        const ZERO_GUID: Uuid = Uuid::from_bytes([0x0; 16]);

        // Pre-defined re-usable variables.
        let table_ptr: *mut u8 = data as *mut u8;

        // Create a location to store the final data.
        let mut retval: Vec<UAPI::CertTableEntry> = vec![];

        // Start parsing the PSP data from the pointers.
        let mut entry: CertTableEntry;

        loop {
            // Dereference the pointer to parse the table data.
            entry = *data;
            let guid: Uuid = Uuid::from_slice(entry.guid.as_slice())?;

            // Once we find a zeroed GUID, we are done.
            if guid == ZERO_GUID {
                break;
            }

            // Calculate the beginning and ending pointers of the raw certificate data.
            let mut cert_bytes: Vec<u8> = vec![];
            let mut cert_addr: *mut u8 = table_ptr.offset(entry.offset as isize) as *mut u8;
            let cert_end: *mut u8 = cert_addr.add(entry.length as usize) as *mut u8;

            // Gather the certificate bytes.
            while cert_addr.ne(&cert_end) {
                cert_bytes.push(*cert_addr);
                cert_addr = cert_addr.add(1usize);
            }

            // Build the Rust-friendly structure and append vector to be returned when
            // we are finished.
            retval.push(UAPI::CertTableEntry::from_guid(
                &guid.hyphenated().to_string(),
                cert_bytes.clone(),
            ));

            // Move the pointer ahead to the next value.
            data = data.offset(1isize);
        }

        Ok(retval)
    }
}

#[repr(C)]
pub struct SnpSetExtConfig {
    /// Address of the SnpConfig or 0 when reported_tcb does not need
    /// to be updated.
    pub config_address: u64,

    /// Address of extended guest request [`CertTableEntry`] buffer or 0 when
    /// previous certificate(s) should be removed via SNP_SET_EXT_CONFIG.
    pub certs_address: u64,

    /// 4K-page aligned length of the buffer holding certificates to be cached.
    pub certs_len: u32,
}

impl From<UAPI::SnpExtConfig> for SnpSetExtConfig {
    fn from(value: UAPI::SnpExtConfig) -> Self {
        let mut config_address: u64 = 0;
        let mut certs_address: u64 = 0;

        if let Some(mut configuration) = value.config {
            config_address = &mut configuration as *mut UAPI::SnpConfig as u64;
        }

        if let Some(mut certificates) = value.certs {
            certs_address = certificates.as_mut_ptr() as u64;
        }

        Self {
            config_address,
            certs_address,
            certs_len: value.certs_len,
        }
    }
}

pub trait TryFromConfig<ConfigType>: From<ConfigType> {
    type TryFromError;

    fn from_uapi(value: &ConfigType, bytes: &mut Vec<u8>) -> Result<Self, Self::TryFromError>;
}

impl TryFromConfig<UAPI::SnpExtConfig> for SnpSetExtConfig {
    type TryFromError = UserApiError;

    fn from_uapi(
        value: &UAPI::SnpExtConfig,
        bytes: &mut Vec<u8>,
    ) -> Result<Self, Self::TryFromError> {
        // Make sure the buffer is is of sufficient size.
        if value.certs_len < bytes.len() as u32 {
            return Err(SnpCertError::BufferOverflow.into());
        }

        // Make sure the buffer length is 4K-page aligned.
        if value.certs_len > 0 && value.certs_len as usize % _4K_PAGE != 0 {
            return Err(SnpCertError::PageMisalignment.into());
        }

        // Copy the existing information from the user.
        let mut retval: SnpSetExtConfig = value.clone().into();

        // When certificates are present, create a pointer to the location, and update the length appropriately.
        if let Some(mut certificates) = value.certs.clone() {
            // Update the bytes vector with correct bytes.
            *bytes = CertTableEntry::uapi_to_vec_bytes(&mut certificates)?;

            // Set the pointers to the updated buffer.
            retval.certs_address = bytes.as_mut_ptr() as u64;
            retval.certs_len = value.certs_len;
        }

        Ok(retval)
    }
}
#[repr(C)]
pub struct SnpGetExtConfig {
    /// Address of the SnpConfig or 0 when reported_tcb should not be
    /// fetched.
    pub config_address: u64,

    /// Address of extended guest request [`CertTableEntry`] buffer or 0 when
    /// certificate(s) should not be fetched.
    pub certs_address: u64,

    /// 4K-page aligned length of the buffer which will hold the fetched certificates.
    pub certs_len: u32,
}
