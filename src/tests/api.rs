// SPDX-License-Identifier: Apache-2.0

use sev::cached_chain;
use sev::firmware::host::types::{
    CertTableEntry, SnpCertType, SnpConfig, SnpExtConfig, TcbVersion,
};
use sev::{certs::sev::Usage, firmware::host::Firmware, Build, Version};

use serial_test::serial;

#[cfg_attr(not(has_sev), ignore)]
#[test]
fn get_identifier() {
    let mut fw = Firmware::open().unwrap();
    let id = fw.get_identifier().unwrap();
    assert_ne!(Vec::from(id), vec![0u8; 64]);
}

#[cfg_attr(not(has_sev), ignore)]
#[test]
fn platform_status() {
    let mut fw = Firmware::open().unwrap();
    let status = fw.snp_platform_status().unwrap();

    println!(
        "Platform status ioctl results:
              version (major, minor): {}.{}
              build id: {}
              guests: {}
              platform tcb microcode version: {}
              platform tcb snp version: {}
              platform tcb tee version: {}
              platform tcb bootloader version: {}
              reported tcb microcode version: {}
              reported tcb snp version: {}
              reported tcb tee version: {}
              reported tcb bootloader version: {}
              state: {}",
        status.build.version.major,
        status.build.version.minor,
        status.build.build,
        status.guests,
        status.tcb.platform_version.microcode,
        status.tcb.platform_version.snp,
        status.tcb.platform_version.tee,
        status.tcb.platform_version.bootloader,
        status.tcb.reported_version.microcode,
        status.tcb.reported_version.snp,
        status.tcb.reported_version.tee,
        status.tcb.reported_version.bootloader,
        status.state
    );
}

fn build_ext_config(cert: bool, cfg: bool) -> SnpExtConfig {
    let test_cfg: SnpConfig = SnpConfig::new(TcbVersion::new(2, 0, 6, 39), 31);

    let cert_table: Vec<CertTableEntry> = vec![
        CertTableEntry::new(SnpCertType::ARK, vec![1; 28]),
        CertTableEntry::new(SnpCertType::ASK, vec![1; 28]),
    ];

    SnpExtConfig {
        config: match cfg {
            true => Some(test_cfg),
            false => None,
        },
        certs: match cert {
            true => Some(cert_table),
            false => None,
        },
        certs_len: match cert {
            true => 2,
            false => 0,
        },
    }
}

#[cfg_attr(not(all(has_sev, feature = "dangerous_hw_tests")), ignore)]
#[ignore]
#[test]
#[serial]
fn snp_set_ext_config_std() {
    let mut fw: Firmware = Firmware::open().unwrap();
    let new_config: SnpExtConfig = build_ext_config(true, true);
    fw.snp_set_ext_config(&new_config).unwrap();
}

#[cfg_attr(not(all(has_sev, feature = "dangerous_hw_tests")), ignore)]
#[ignore]
#[test]
#[serial]
fn snp_get_ext_config_std() {
    let mut fw: Firmware = Firmware::open().unwrap();
    let new_config: SnpExtConfig = build_ext_config(true, true);
    fw.snp_set_ext_config(&new_config).unwrap();
    let hw_config: SnpExtConfig = fw.snp_get_ext_config().unwrap();
    assert_eq!(new_config, hw_config);
}

#[cfg_attr(not(all(has_sev, feature = "dangerous_hw_tests")), ignore)]
#[ignore]
#[test]
#[serial]
fn snp_get_ext_config_cert_only() {
    let mut fw: Firmware = Firmware::open().unwrap();
    let new_config: SnpExtConfig = build_ext_config(true, false);
    fw.snp_set_ext_config(&new_config).unwrap();
    let hw_config: SnpExtConfig = fw.snp_get_ext_config().unwrap();
    assert_eq!(new_config, hw_config);
}

#[cfg_attr(not(all(has_sev, feature = "dangerous_hw_tests")), ignore)]
#[ignore]
#[test]
#[serial]
fn snp_get_ext_config_cfg_only() {
    let mut fw: Firmware = Firmware::open().unwrap();
    let new_config: SnpExtConfig = build_ext_config(false, true);
    fw.snp_set_ext_config(&new_config).unwrap();
    let hw_config: SnpExtConfig = fw.snp_get_ext_config().unwrap();
    assert_eq!(new_config, hw_config);
}
