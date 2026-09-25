use std::process::Command;

#[test]
fn help_and_unknown_option() {
    let binary = env!("CARGO_BIN_EXE_bench");
    let help = Command::new(binary).arg("--help").output().unwrap();
    assert!(help.status.success());
    assert!(String::from_utf8_lossy(&help.stdout).contains("--config"));
    let bad = Command::new(binary)
        .args(["--unknown", "value"])
        .output()
        .unwrap();
    assert!(!bad.status.success());
    assert!(String::from_utf8_lossy(&bad.stderr).contains("unknown argument"));
}
#[test]
fn invalid_configuration_is_rejected_before_running() {
    let path = std::env::temp_dir().join(format!("lrdas-invalid-{}.json", std::process::id()));
    std::fs::write(&path,r#"{"name":"bad","params":{"ell":6,"m":16,"r":0,"a":4,"b":0},"samples":1,"warmup_ms":0,"min_sample_ms":1,"max_iterations":1,"slow_samples":1,"seed":1,"include_streaming":false}"#).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_bench"))
        .args([
            "--config",
            path.to_str().unwrap(),
            "--out",
            "unused-invalid-output",
        ])
        .output()
        .unwrap();
    std::fs::remove_file(path).unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("invalid code dimensions"));
}
