// SPDX-License-Identifier: Apache-2.0

mod ioctl;
pub(crate) mod types;

use ioctl::*;

use crate::error::Error;

use std::fs::{File, OpenOptions};

use crate::{
    error::{Indeterminate, RawFwError, UserApiError, VmmError},
    firmware::{guest::types::SnpDerivedKey, host::types as UAPI, linux::host::types::*},
};

use self::types::{
    SnpDerivedKeyReq, SnpDerivedKeyRsp, SnpExtReportReq, SnpReportReq, SnpReportRsp,
};
pub const INVALID_CERT_BUFFER: u64 = 0x0000000100000000;

pub fn snp_get_request(
    message_version: Option<u8>,
    report_request: &mut SnpReportReq,
) -> Result<SnpReportRsp, UserApiError> {
    let mut report_response: SnpReportRsp = Default::default();
    let mut fw: Firmware = Firmware::open()?;
    fw.snp_get_report(message_version, report_request, &mut report_response)?;
    Ok(report_response)
}

pub fn snp_get_derived_key(
    message_version: Option<u8>,
    derived_key_request: &mut SnpDerivedKey,
) -> Result<SnpDerivedKeyRsp, UserApiError> {
    let mut ffi_derived_key_request: SnpDerivedKeyReq = derived_key_request.into();
    let mut ffi_derived_key_response: SnpDerivedKeyRsp = Default::default();

    let mut fw: Firmware = Firmware::open()?;
    fw.snp_get_derived_key(
        message_version,
        &mut ffi_derived_key_request,
        &mut ffi_derived_key_response,
    )?;
    Ok(ffi_derived_key_response)
}

pub fn snp_get_ext_report(
    message_version: Option<u8>,
    report_request: &mut SnpReportReq,
) -> Result<(SnpReportRsp, Vec<UAPI::CertTableEntry>), UserApiError> {
    let mut report_response: SnpReportRsp = Default::default();
    let mut certificates: Vec<UAPI::CertTableEntry> = vec![];

    let mut fw: Firmware = Firmware::open()?;
    fw.snp_get_ext_report(
        message_version,
        report_request,
        &mut report_response,
        &mut certificates,
    )?;

    Ok((report_response, certificates))
}

/// Checks the `fw_err` field on the [`SnpGuestRequest`] structure
/// to make sure that no errors were encountered by the VMM or the AMD
/// Secure Processor.
fn check_fw_err(raw_error: RawFwError) -> Result<(), UserApiError> {
    if raw_error != 0.into() {
        let (upper, lower): (u32, u32) = raw_error.into();

        if upper != 0 {
            return Err(VmmError::from(upper).into());
        }

        if lower != 0 {
            match lower.into() {
                Indeterminate::Known(error) => return Err(error.into()),
                Indeterminate::Unknown => return Err(UserApiError::Unknown),
            }
        }
    }
    Ok(())
}

/// A handle to the SEV, SEV-ES, or SEV-SNP platform.
struct Firmware(File);

impl Firmware {
    /// Generate a new file handle to the SEV guest platform.
    fn open() -> std::io::Result<Firmware> {
        Ok(Firmware(
            OpenOptions::new()
                .read(true)
                .write(true)
                .open("/dev/sev-guest")?,
        ))
    }

    /// Request an attestation report from the PSP
    ///
    /// # Arguments
    ///
    /// * `message_version` - (Optional) Used for the SnpGuestRequest, specifies the message version number defaults to 1.
    /// * `report_request` - an SnpReportReq object with its associated data for requesting the attestation report.
    ///
    fn snp_get_report(
        &mut self,
        message_version: Option<u8>,
        report_request: &mut SnpReportReq,
        report_response: &mut SnpReportRsp,
    ) -> Result<(), UserApiError> {
        let mut request: SnpGuestRequest<SnpReportReq, SnpReportRsp> =
            SnpGuestRequest::new(message_version, report_request, report_response);

        SNP_GET_REPORT.ioctl(&mut self.0, &mut request)?;

        check_fw_err(request.fw_err.into())?;

        Ok(())
    }

    /// Fetches a derived key from the PSP
    ///
    /// # Arguments
    ///
    /// * `message_version` - (Optional) Used for the SnpGuestRequest, specifies the message version number defaults to 1.
    /// * `derived_key_request` - an SnpDerivedKeyReq object with its associated data for generating a derived key.
    ///
    fn snp_get_derived_key(
        &mut self,
        message_version: Option<u8>,
        derived_key_request: &mut SnpDerivedKeyReq,
        derived_key_response: &mut SnpDerivedKeyRsp,
    ) -> Result<(), UserApiError> {
        let mut request: SnpGuestRequest<SnpDerivedKeyReq, SnpDerivedKeyRsp> =
            SnpGuestRequest::new(message_version, derived_key_request, derived_key_response);

        SNP_GET_DERIVED_KEY.ioctl(&mut self.0, &mut request)?;

        check_fw_err(request.fw_err.into())?;

        Ok(())
    }

    /// Request an extended attestation report from the PSP
    ///
    /// # Arguments
    ///
    /// * `message_version` - (Optional) Used for the SnpGuestRequest, specifies the message version number defaults to 1.
    /// * `report_request` - an SnpReportReq object with its associated data.
    ///
    fn snp_get_ext_report(
        &mut self,
        message_version: Option<u8>,
        report_request: &mut SnpReportReq,
        report_response: &mut SnpReportRsp,
        certificates: &mut Vec<UAPI::CertTableEntry>,
    ) -> Result<(), UserApiError> {
        // Define a buffer to store the certificates in.
        let mut certificate_bytes: Vec<u8>;

        // Due to the complex buffer allocation, we will take the SnpReportReq
        // provided by the caller, and create an extended report request object
        // for them.
        let mut ext_report_request: SnpExtReportReq = SnpExtReportReq::new(report_request);

        // Construct the object needed to perform the IOCTL request.
        // *NOTE:* This is __important__ because a fw_err value which matches
        // [`INVALID_CERT_BUFFER`] will indicate the buffer was not large
        // enough.
        let mut guest_request: SnpGuestRequest<SnpExtReportReq, SnpReportRsp> =
            SnpGuestRequest::new(message_version, &mut ext_report_request, report_response);

        // KEEP for Kernels before 47894e0f (5.19), as userspace broke at that hash.
        if let Err(ioctl_error) = SNP_GET_EXT_REPORT.ioctl(&mut self.0, &mut guest_request) {
            match guest_request.fw_err.into() {
                VmmError::InvalidCertificatePageLength => (),
                VmmError::RateLimitRetryRequest => {
                    return Err(VmmError::RateLimitRetryRequest.into())
                }
                _ => return Err(ioctl_error.into()),
            }

            // Eventually the code below will be moved back into this scope.
        }

        // The kernel patch by pgonda@google.com in kernel hash 47894e0f
        // changed the ioctl return to succeed instead of returning an
        // error when encountering an invalid certificate length. This was
        // done to keep the cryptography safe, so we will now just check
        // the guest_request.fw_err for a new value.
        //
        // Check to see if the buffer needs to be resized. If it does, the
        // we need to resize the buffer to the correct size, and
        // re-request for the certificates.
        if guest_request.fw_err == INVALID_CERT_BUFFER {
            certificate_bytes = vec![0u8; ext_report_request.certs_len as usize];
            ext_report_request.certs_address = certificate_bytes.as_mut_ptr() as u64;
            let mut guest_request_retry: SnpGuestRequest<SnpExtReportReq, SnpReportRsp> =
                SnpGuestRequest::new(message_version, &mut ext_report_request, report_response);
            SNP_GET_EXT_REPORT.ioctl(&mut self.0, &mut guest_request_retry)?;
        } else if guest_request.fw_err != 0 {
            // This shouldn't be possible, but if it happens, throw an error.
            return Err(UserApiError::FirmwareError(Error::InvalidConfig));
        }

        unsafe {
            if let Some(linux_cert_table) =
                (ext_report_request.certs_address as *mut CertTableEntry).as_mut()
            {
                // let parsed_table = &mut FFI::CertTableEntry::parse_table(linux_cert_table as &mut FFI::CertTableEntry)?;
                *certificates =
                    CertTableEntry::parse_table(linux_cert_table as &mut CertTableEntry)?;
            }
        }

        // Return both the Attestation Report, as well as the Cert Table.
        Ok(())
    }
}
