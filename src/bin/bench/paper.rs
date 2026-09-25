//! Reproduce only the two benchmark tables in Section 8.1.
use lrdas_artifact::{
    domain::{Domain, Params},
    fixture, Error, Result,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    hint::black_box,
    io::{BufWriter, Write},
    path::{Path, PathBuf},
    time::Instant,
};
#[path = "experiments.rs"]
mod experiments;
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Config {
    name: String,
    params: Params,
    #[serde(default)]
    reconstruction_params: Vec<Params>,
    samples: usize,
    warmup_ms: u64,
    min_sample_ms: u64,
    max_iterations: u64,
    slow_samples: usize,
    seed: u64,
}
struct Runner {
    writer: BufWriter<File>,
    config: Config,
    run_id: String,
    process_run_id: usize,
    rows: usize,
}
impl Runner {
    fn bench<T, F: FnMut() -> Result<T>>(
        &mut self,
        scheme: &str,
        op: &str,
        size: usize,
        cache: &str,
        slow: bool,
        mut f: F,
    ) -> Result<()> {
        eprintln!("{} / {} / {} ({})", self.run_id, scheme, op, size);
        let warm = Instant::now();
        if !slow {
            while warm.elapsed().as_millis() < u128::from(self.config.warmup_ms) {
                black_box(f()?);
            }
        }
        let pilot_ns = if slow {
            0
        } else {
            let pilot = Instant::now();
            black_box(f()?);
            pilot.elapsed().as_nanos().max(1)
        };
        let iterations = if slow {
            1
        } else {
            ((u128::from(self.config.min_sample_ms) * 1_000_000 / pilot_ns)
                .max(1)
                .min(u128::from(self.config.max_iterations))) as u64
        };
        let count = if slow {
            self.config.slow_samples
        } else {
            self.config.samples
        };
        for sample_id in 0..count {
            let start = Instant::now();
            for _ in 0..iterations {
                black_box(f()?);
            }
            let elapsed_ns = start.elapsed().as_nanos();
            let row = json!({"schema_version":1,"run_id":self.run_id,"process_run_id":self.process_run_id,"scheme":scheme,"backend":"arkworks-0.4","profile":self.config.name,"operation":op,"workload_id":format!("{scheme}/{op}/{size}/{cache}"),"input_size":size,"sample_id":sample_id,"iterations":iterations,"elapsed_ns":elapsed_ns as u64,"threads":1,"cache_policy":cache,"seed":self.config.seed,"fixture_id":format!("chacha20-v1-{}",self.config.seed),"status":"ok","measurement_kind":"measured","timing_scope":"wall_clock_library_or_role_as_documented","warmup_ms":if slow{0}else{self.config.warmup_ms},"pilot_ns":pilot_ns as u64});
            serde_json::to_writer(&mut self.writer, &row).map_err(err)?;
            writeln!(&mut self.writer).map_err(err)?;
            self.rows += 1;
        }
        self.writer.flush().map_err(err)?;
        Ok(())
    }
}
fn err(e: impl std::fmt::Display) -> Error {
    Error(e.to_string())
}
fn run(config: Config, out: &Path, process_run_id: usize, table: u8) -> Result<()> {
    let config = Config {
        params: config.params.validate()?,
        ..config
    };
    if config.samples == 0
        || config.samples > 10000
        || config.slow_samples == 0
        || config.max_iterations == 0
    {
        return Err(err("invalid measurement settings"));
    }
    if config.params.a() == config.params.ell() || config.params.b() != 0 {
        return Err(err(
            "benchmark comparison requires b=0 and at least one parity group",
        ));
    }
    fs::create_dir_all(out).map_err(err)?;
    let path = out.join(format!("run-{process_run_id}.jsonl"));
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .map_err(err)?;
    let status_path = out.join(format!("run-{process_run_id}.status.json"));
    fs::write(
        &status_path,
        serde_json::to_vec_pretty(&json!({"status":"running","config":config})).map_err(err)?,
    )
    .map_err(err)?;
    let total_start = Instant::now();
    let init = Instant::now();
    let domain = Domain::new(config.params)?;
    let domain_ms = init.elapsed().as_secs_f64() * 1000.;
    let init = Instant::now();
    let srs = fixture::setup(config.params.r(), 7001)?;
    let setup_ms = init.elapsed().as_secs_f64() * 1000.;
    let run_id = format!("{}-{}", config.name, process_run_id);
    let mut runner = Runner {
        writer: BufWriter::new(file),
        config: config.clone(),
        run_id,
        process_run_id,
        rows: 0,
    };
    let mut meta = vec![];
    let result = experiments::run(&mut runner, &domain, &srs, &mut meta, table);
    runner.writer.flush().map_err(err)?;
    let status = if result.is_ok() { "complete" } else { "failed" };
    let memory = fs::read_to_string("/proc/self/status")
        .unwrap_or_default()
        .lines()
        .filter(|l| l.starts_with("VmHWM:") || l.starts_with("Threads:"))
        .collect::<Vec<_>>()
        .join("; ");
    let source_version = fs::read_to_string(out.join("environment.json"))
        .ok()
        .and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok());
    let manifest = json!({"schema_version":1,"table":table,"status":status,"error":result.as_ref().err().map(ToString::to_string),"process_run_id":process_run_id,"config":config,"rows":runner.rows,"domain_setup_ms":domain_ms,"srs_fixture_ms":setup_ms,"srs_id":format!("{:x}",Sha256::digest(srs.id())),"srs_g1_payload_bytes":srs.r()*48,"srs_g2_payload_bytes":(srs.r()+1)*96,"roles":meta,"elapsed_seconds":total_start.elapsed().as_secs_f64(),"whole_runner_high_water":memory,"environment":source_version});
    fs::write(
        status_path,
        serde_json::to_vec_pretty(&manifest).map_err(err)?,
    )
    .map_err(err)?;
    result
}

/// One display/export table. Units are explicit; CSV keeps numeric cells numeric.
struct Table {
    number: u8,
    title: String,
    headers: Vec<String>,
    rows: Vec<Vec<String>>,
}
impl Table {
    fn new(number: u8, title: String, headers: &[&str]) -> Self {
        Self {
            number,
            title,
            headers: headers.iter().map(|s| s.to_string()).collect(),
            rows: vec![],
        }
    }
    fn widths(&self) -> Vec<usize> {
        self.headers
            .iter()
            .enumerate()
            .map(|(i, h)| {
                self.rows
                    .iter()
                    .map(|r| r[i].len())
                    .chain(std::iter::once(h.len()))
                    .max()
                    .unwrap()
            })
            .collect()
    }
    fn print_row(row: &[String], widths: &[usize]) {
        println!(
            "| {} |",
            row.iter()
                .zip(widths)
                .map(|(s, w)| format!("{s:>w$}"))
                .collect::<Vec<_>>()
                .join(" | ")
        );
    }
    fn print(&self) {
        println!("\nTable {}: {}", self.number, self.title);
        let widths = self.widths();
        Self::print_row(&self.headers, &widths);
        println!(
            "|-{}-|",
            widths
                .iter()
                .map(|n| "-".repeat(*n))
                .collect::<Vec<_>>()
                .join("-|-")
        );
        for row in &self.rows {
            Self::print_row(row, &widths);
        }
    }
    fn save(&self, out: &Path) -> Result<()> {
        fn csv_cell(s: &str) -> String {
            if s.contains([',', '"', '\n', '\r']) {
                format!("\"{}\"", s.replace('"', "\"\""))
            } else {
                s.to_owned()
            }
        }
        let csv = std::iter::once(&self.headers)
            .chain(&self.rows)
            .map(|row| {
                row.iter()
                    .map(|s| csv_cell(s))
                    .collect::<Vec<_>>()
                    .join(",")
            })
            .collect::<Vec<_>>()
            .join("\n")
            + "\n";
        fn tex(s: &str) -> String {
            s.chars()
                .map(|c| match c {
                    '&' => r"\&".into(),
                    '%' => r"\%".into(),
                    '_' => r"\_".into(),
                    '#' => r"\#".into(),
                    '$' => r"\$".into(),
                    '{' => r"\{".into(),
                    '}' => r"\}".into(),
                    '\\' => r"\textbackslash{}".into(),
                    '^' => r"\textasciicircum{}".into(),
                    '~' => r"\textasciitilde{}".into(),
                    _ => c.to_string(),
                })
                .collect()
        }
        let mut latex=format!("% Generated from measured runs; requires booktabs.\n\\begin{{table}}[t]\n\\centering\n\\small\n\\caption{{{}}}\n\\label{{tab:runtime-{}}}\n\\begin{{tabular}}{{@{{}}l{}@{{}}}}\n\\toprule\n",
            tex(&self.title),self.number,"r".repeat(self.headers.len()-1));
        for (i, row) in std::iter::once(&self.headers).chain(&self.rows).enumerate() {
            latex.push_str(&row.iter().map(|s| tex(s)).collect::<Vec<_>>().join(" & "));
            latex.push_str(" \\\\\n");
            if i == 0 {
                latex.push_str("\\midrule\n");
            }
        }
        latex.push_str("\\bottomrule\n\\end{tabular}\n\\end{table}\n");
        fs::write(out.join(format!("table{}.csv", self.number)), csv).map_err(err)?;
        fs::write(out.join(format!("table{}.tex", self.number)), latex).map_err(err)?;
        Ok(())
    }
}
#[derive(Deserialize)]
struct Sample {
    scheme: String,
    operation: String,
    cache_policy: String,
    sample_id: usize,
    iterations: u64,
    elapsed_ns: u64,
    status: String,
}
type Key = (String, String, String);
struct Summary {
    times: std::collections::BTreeMap<Key, f64>,
    sizes: std::collections::BTreeMap<String, (u64, u64)>,
}
impl Summary {
    fn time(&self, scheme: &str, operation: &str, cache: &str) -> Result<String> {
        let ms = self
            .times
            .get(&(scheme.into(), operation.into(), cache.into()))
            .ok_or_else(|| err("missing measured workload"))?;
        Ok(format!("{ms:.1}"))
    }
}
fn summarize(out: &Path, runs: usize, table: u8, config: &Config) -> Result<Summary> {
    use std::collections::{BTreeMap, BTreeSet};
    let mut means: BTreeMap<Key, Vec<f64>> = BTreeMap::new();
    let mut sizes = BTreeMap::new();
    for run in 0..runs {
        let status: serde_json::Value = serde_json::from_slice(
            &fs::read(out.join(format!("run-{run}.status.json"))).map_err(err)?,
        )
        .map_err(err)?;
        if status["status"] != "complete"
            || status["table"] != table
            || status["config"]["params"] != serde_json::to_value(config.params).map_err(err)?
        {
            return Err(err("incomplete or mismatched benchmark run"));
        }
        for role in status["roles"]
            .as_array()
            .ok_or_else(|| err("missing roles"))?
        {
            if let Some(name) = role["variant"].as_str() {
                let pair = (
                    role["commitment_bytes"]
                        .as_u64()
                        .ok_or_else(|| err("missing size"))?,
                    role["g1_srs_bytes"]
                        .as_u64()
                        .ok_or_else(|| err("missing SRS size"))?,
                );
                if sizes
                    .insert(name.to_owned(), pair)
                    .is_some_and(|old| old != pair)
                {
                    return Err(err("inconsistent serialized sizes"));
                }
            }
        }
        let mut samples: BTreeMap<Key, Vec<f64>> = BTreeMap::new();
        let mut seen = BTreeSet::new();
        for line in fs::read_to_string(out.join(format!("run-{run}.jsonl")))
            .map_err(err)?
            .lines()
        {
            let row: Sample = serde_json::from_str(line).map_err(err)?;
            if row.status != "ok" || row.iterations == 0 {
                return Err(err("invalid measurement sample"));
            }
            let key = (row.scheme, row.operation, row.cache_policy);
            if !seen.insert((key.clone(), row.sample_id)) {
                return Err(err("duplicate sample"));
            }
            samples
                .entry(key)
                .or_default()
                .push(row.elapsed_ns as f64 / row.iterations as f64 / 1e6);
        }
        if samples.len() != if table == 2 { 8 } else { 2 } {
            return Err(err("missing workloads"));
        }
        for (key, xs) in samples {
            let expected = if key.1 == "variant_light_client" {
                config.samples
            } else {
                config.slow_samples
            };
            if xs.len() != expected {
                return Err(err("incomplete sample count"));
            }
            means
                .entry(key)
                .or_default()
                .push(xs.iter().sum::<f64>() / xs.len() as f64);
        }
    }
    let mut times = BTreeMap::new();
    for (key, xs) in means {
        if xs.len() != runs {
            return Err(err("workloads differ across processes"));
        }
        times.insert(key, xs.iter().sum::<f64>() / runs as f64);
    }
    Ok(Summary { times, sizes })
}
fn params_label(p: Params) -> String {
    format!("({},{},{},{},{})", p.ell(), p.m(), p.r(), p.a(), p.b())
}
fn validate(config: &Config, table: u8) -> Result<()> {
    let p = config.params.validate()?;
    if config.samples == 0
        || config.samples > 10000
        || config.slow_samples == 0
        || config.slow_samples > 10000
        || config.max_iterations == 0
    {
        return Err(err("invalid sample settings"));
    }
    if p.b() != 0 || p.a() >= p.ell() {
        return Err(err("comparison requires b=0 and a<ell"));
    }
    if table == 3 {
        if p.m() < p.ell()
            || (p.ell() * (p.m() - p.r() + 1)).div_ceil(p.m()) > p.ell() - p.a()
            || (p.ell() - 1) * (p.r() - 1) <= p.m() * (p.a() - 1)
        {
            return Err(err(format!(
                "{} does not satisfy Proposition 7 recovery conditions",
                params_label(p)
            )));
        }
    } else if p.degree() <= p.m() {
        return Err(err(
            "Profile B implementation requires D>m for its long SRS",
        ));
    }
    Ok(())
}
fn measure(config: &Config, out: &Path, runs: usize, table: u8) -> Result<Summary> {
    fs::create_dir(out).map_err(err)?;
    let path = out.join("config.json");
    fs::write(&path, serde_json::to_vec_pretty(config).map_err(err)?).map_err(err)?;
    let executable = std::env::current_exe().map_err(err)?;
    for n in 0..runs {
        let log = File::create(out.join(format!("run-{n}.log"))).map_err(err)?;
        let status = std::process::Command::new(&executable)
            .arg("--config")
            .arg(&path)
            .arg("--out")
            .arg(out)
            .arg("--table")
            .arg(table.to_string())
            .arg("--run")
            .arg(n.to_string())
            .stderr(log)
            .status()
            .map_err(err)?;
        if !status.success() {
            return Err(err(format!(
                "measurement process {n} failed; see {}",
                out.display()
            )));
        }
    }
    summarize(out, runs, table, config)
}
pub(super) fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.iter().any(|a| a == "--help") {
        println!("Usage: bench [--table 2|3|all] [--config reference.json] [--out NEW_DIRECTORY] [--runs 3]\n\
Table 2: A/B commitments and client verification at config.params.\n\
Table 3: full reconstruction for every config.reconstruction_params entry (or config.params if omitted).\n\
Prints tables and saves table2/3.csv and table2/3.tex. Existing output directories are not overwritten.");
        return Ok(());
    }
    let mut out = PathBuf::from("results");
    let mut config_path = PathBuf::from("reference.json");
    let mut selected = "all".to_string();
    let mut number = None;
    let mut runs = 3usize;
    let mut i = 0;
    while i < args.len() {
        let v = args.get(i + 1).ok_or("missing argument value")?;
        match args[i].as_str() {
            "--out" => out = PathBuf::from(v),
            "--config" => config_path = PathBuf::from(v),
            "--table" => selected = v.clone(),
            "--runs" => runs = v.parse()?,
            "--run" => number = Some(v.parse::<usize>()?),
            _ => return Err(format!("unknown argument {}", args[i]).into()),
        }
        i += 2;
    }
    if !["2", "3", "all"].contains(&selected.as_str()) || !(1..=100).contains(&runs) {
        return Err("use --table 2|3|all and --runs between 1 and 100".into());
    }
    let config: Config = serde_json::from_slice(&fs::read(config_path)?)?;
    if let Some(number) = number {
        let table = selected.parse::<u8>()?;
        validate(&config, table)?;
        let mut config = config;
        config.seed = config.seed.wrapping_add(number as u64);
        run(config, &out, number, table)?;
        return Ok(());
    }
    let mut cases = vec![];
    if selected != "3" {
        validate(&config, 2)?;
    }
    if selected != "2" {
        let params = if config.reconstruction_params.is_empty() {
            vec![config.params]
        } else {
            config.reconstruction_params.clone()
        };
        for p in params {
            if cases.iter().any(|c: &Config| c.params == p) {
                return Err("duplicate reconstruction parameters".into());
            }
            let mut c = config.clone();
            c.params = p;
            c.reconstruction_params.clear();
            validate(&c, 3)?;
            cases.push(c);
        }
    }
    fs::create_dir(&out)?;
    fs::write(out.join("config.json"), serde_json::to_vec_pretty(&config)?)?;
    fs::write(
        out.join("execution.json"),
        serde_json::to_vec_pretty(&json!({
            "table":selected,"runs":runs,"timings":"mean of per-process means, milliseconds",
            "table3_input":"authenticated values; input verification and network excluded"
        }))?,
    )?;
    if selected != "3" {
        eprintln!("Measuring Table 2; per-process logs are saved in the output directory.");
        let summary = measure(&config, &out.join("table2-runs"), runs, 2)?;
        let mut report = Table::new(
            2,
            format!(
                "Profiles A/B at {}; {} independent process(es)",
                params_label(config.params),
                runs
            ),
            &[
                "Metric",
                "Unit",
                "LR-DAS A",
                "Product A",
                "LR-DAS B",
                "Product B",
            ],
        );
        let schemes = ["lrdas_a", "product_a", "lrdas_b", "product_b"];
        for (label, op, cache) in [
            (
                "Commitment generation",
                "variant_header_commit",
                "public_srs",
            ),
            ("Client verification", "variant_light_client", "cold"),
        ] {
            let mut row = vec![label.into(), "ms".into()];
            for scheme in schemes {
                row.push(summary.time(scheme, op, cache)?);
            }
            report.rows.push(row);
        }
        for (label, which) in [("Commitment size", 0), ("G1 SRS size", 1)] {
            let mut row = vec![label.into(), "B".into()];
            for scheme in schemes {
                let pair = summary.sizes.get(scheme).ok_or("missing commitment size")?;
                row.push(if which == 0 {
                    pair.0.to_string()
                } else {
                    pair.1.to_string()
                });
            }
            report.rows.push(row);
        }
        report.save(&out)?;
        report.print();
    }
    if selected != "2" {
        let mut report = Table::new(
            3,
            format!(
                "Full reconstruction under Proposition 7; {} independent process(es) per row",
                runs
            ),
            &["ell", "m", "r", "a", "b", "LR-DAS (ms)", "Product (ms)"],
        );
        eprintln!(
            "Measuring Table 3: {} parameter sets, {} processes each.",
            cases.len(),
            runs
        );
        for (i, case) in cases.iter().enumerate() {
            let summary = measure(case, &out.join(format!("table3-case-{}", i + 1)), runs, 3)?;
            let p = case.params;
            report.rows.push(vec![
                p.ell().to_string(),
                p.m().to_string(),
                p.r().to_string(),
                p.a().to_string(),
                p.b().to_string(),
                summary.time("lrdas_a", "diagonal_full_decode", "accepted_values")?,
                summary.time("product_a", "diagonal_full_decode", "accepted_values")?,
            ]);
            report.save(&out)?;
            if i == 0 {
                println!("\nTable 3: {}", report.title);
                println!(
                    "{:>5} {:>7} {:>7} {:>5} {:>3} {:>14} {:>14}",
                    "ell", "m", "r", "a", "b", "LR-DAS (ms)", "Product (ms)"
                );
            }
            let row = report.rows.last().unwrap();
            println!(
                "{:>5} {:>7} {:>7} {:>5} {:>3} {:>14} {:>14}",
                row[0], row[1], row[2], row[3], row[4], row[5], row[6]
            );
            std::io::stdout().flush()?;
        }
    }
    println!("\nCSV and LaTeX: {}", out.display());
    Ok(())
}
