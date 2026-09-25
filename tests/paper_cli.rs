use serde_json::json;
use std::{
    fs,
    path::PathBuf,
    process::Command,
    sync::atomic::{AtomicUsize, Ordering},
};
static NEXT: AtomicUsize = AtomicUsize::new(0);
struct Dir(PathBuf);
impl Dir {
    fn new() -> Self {
        let p = std::env::temp_dir().join(format!(
            "lrdas-cli-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&p).unwrap();
        Self(p)
    }
}
impl Drop for Dir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn config() -> serde_json::Value {
    json!({"name":"cli-correctness","params":{"ell":6,"m":16,"r":12,"a":4,"b":0},
        "reconstruction_params":[{"ell":6,"m":16,"r":12,"a":4,"b":0},{"ell":6,"m":32,"r":24,"a":4,"b":0}],
        "samples":1,"warmup_ms":0,"min_sample_ms":0,"max_iterations":1,"slow_samples":1,"seed":27})
}
fn exec(path: &std::path::Path, out: &std::path::Path, table: &str) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_bench"))
        .args(["--table", table, "--runs", "2", "--config"])
        .arg(path)
        .arg("--out")
        .arg(out)
        .output()
        .unwrap()
}
#[test]
fn both_tables_use_measured_rows_and_export_csv_and_latex() {
    let dir = Dir::new();
    let cfg = dir.0.join("config.json");
    fs::write(&cfg, config().to_string()).unwrap();
    let out = dir.0.join("results");
    let result = exec(&cfg, &out, "all");
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let stdout = String::from_utf8(result.stdout).unwrap();
    assert!(stdout.contains("Table 2:") && stdout.contains("Table 3:"));
    let csv2 = fs::read_to_string(out.join("table2.csv")).unwrap();
    assert_eq!(csv2.lines().count(), 5);
    assert!(csv2.contains("Commitment size,B,192,192,384,384"));
    let csv3 = fs::read_to_string(out.join("table3.csv")).unwrap();
    assert_eq!(csv3.lines().count(), 3);
    assert!(csv3.lines().nth(1).unwrap().starts_with("6,16,12,4,0,"));
    assert!(csv3.lines().nth(2).unwrap().starts_with("6,32,24,4,0,"));
    for (i, line) in csv3.lines().skip(1).enumerate() {
        let cells: Vec<_> = line.split(',').collect();
        for (col, scheme) in [(5, "lrdas_a"), (6, "product_a")] {
            let mut total = 0.;
            for run in 0..2 {
                let raw =
                    fs::read_to_string(out.join(format!("table3-case-{}/run-{run}.jsonl", i + 1)))
                        .unwrap();
                let rows: Vec<serde_json::Value> = raw
                    .lines()
                    .map(|s| serde_json::from_str(s).unwrap())
                    .collect();
                assert_eq!(rows.len(), 2);
                let row = rows.iter().find(|r| r["scheme"] == scheme).unwrap();
                total += row["elapsed_ns"].as_u64().unwrap() as f64
                    / row["iterations"].as_u64().unwrap() as f64
                    / 1e6;
            }
            assert_eq!(cells[col], format!("{:.1}", total / 2.));
        }
    }
    for number in [2, 3] {
        let tex = fs::read_to_string(out.join(format!("table{number}.tex"))).unwrap();
        assert!(tex.contains("\\begin{tabular}{@{}l"));
        assert!(tex.contains(" \\\\\n\\midrule"));
        assert!(tex.ends_with("\\end{table}\n"));
    }
    assert!(!exec(&cfg, &out, "3").status.success());
    assert_eq!(fs::read_to_string(out.join("table3.csv")).unwrap(), csv3);
}
#[test]
fn invalid_reconstruction_is_rejected_before_measurements() {
    let dir = Dir::new();
    let cfg = dir.0.join("config.json");
    let mut c = config();
    c["reconstruction_params"][1]["a"] = json!(5);
    fs::write(&cfg, c.to_string()).unwrap();
    let out = dir.0.join("results");
    let result = exec(&cfg, &out, "3");
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr).contains("Proposition 7"));
    assert!(!out.exists());
}
