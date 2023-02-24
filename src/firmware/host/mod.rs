// SPDX-License-Identifier: Apache-2.0
pub mod types;

use super::linux::host as FFI;
use crate::error::*;
use types::*;

/// Query the AMD Secure Processor for the SEV-SNP platform status.
pub fn snp_platform_status() -> Result<SnpPlatformStatus, Indeterminate<Error>> {
    FFI::snp_platform_status()
}

/// Fetch the SEV-SNP Extended Configuration from its previous configuration.
pub fn snp_get_ext_config() -> Result<SnpExtConfig, UserApiError> {
    FFI::snp_get_ext_config()
}

/// Set the SEV-SNP Extended Configuration for the AMD Secure Processor.
pub fn snp_set_ext_config(new_config: SnpExtConfig) -> Result<bool, UserApiError> {
    FFI::snp_set_ext_config(&new_config)
}

/// Expose this function for parsing raw data types into a vector of CertTableEntry objects.
pub fn parse_table(data: RawData) -> Result<Vec<CertTableEntry>, uuid::Error> {
    FFI::parse_table(data)
}
