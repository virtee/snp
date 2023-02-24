// SPDX-License-Identifier: Apache-2.0

pub mod types;

use super::linux::guest as FFI;
use crate::{error::*, firmware::host::types::CertTableEntry};
use types::*;

/// Requests an attestation report from the AMD Secure Processor.
pub fn snp_get_report(
    message_version: Option<u8>,
    mut report_request: SnpReportReq,
) -> Result<AttestationReport, UserApiError> {
    let response: SnpReportRsp = FFI::snp_get_request(message_version, &mut report_request)?;
    Ok(response.report)
}

/// Requests a new cryptographic derived key from the AMD Secure Processor.
pub fn snp_get_derived_key(
    message_version: Option<u8>,
    mut derived_key_request: SnpDerivedKey,
) -> Result<[u8; 32], UserApiError> {
    let response = FFI::snp_get_derived_key(message_version, &mut derived_key_request)?;
    Ok(response.key)
}

/// Requests an extended attestation report from the AMD Secure Processor.
///
/// This behave similarly to [`snp_get_report`](self::snp_get_report), but will
/// also retreive a vector of certificates stored in they hypervisor which were
/// provided by the Host.
pub fn snp_get_ext_report(
    message_version: Option<u8>,
    mut report_request: SnpReportReq,
) -> Result<(AttestationReport, Vec<CertTableEntry>), UserApiError> {
    let response = FFI::snp_get_ext_report(message_version, &mut report_request)?;
    Ok((response.0.report, response.1))
}
