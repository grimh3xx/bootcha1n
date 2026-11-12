//! The demo fixture must keep producing the findings shown in docs/demo.svg.
use std::process::Command;

#[test]
fn demo_fixture_findings() {
    let fx = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/demo");
    let out = Command::new(env!("CARGO_BIN_EXE_bootcha1n"))
        .args([
            "--json",
            "--efivars",
            &format!("{fx}/efivars"),
            "--eventlog",
            &format!("{fx}/eventlog.bin"),
            "--pcrs",
            &format!("{fx}/tpm"),
        ])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(4), "critical finding sets exit 4");
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let ids: Vec<&str> = v["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["id"].as_str().unwrap())
        .collect();
    for id in ["BOOT-003", "BOOT-004", "BOOT-008", "BOOT-013", "TPM-001"] {
        assert!(ids.contains(&id), "{id} missing from {ids:?}");
    }
    let mismatched: Vec<u64> = v["measured_boot"]["pcrs"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|r| r["matches"] == false)
        .map(|r| r["pcr"].as_u64().unwrap())
        .collect();
    assert_eq!(mismatched, vec![4]);
}
