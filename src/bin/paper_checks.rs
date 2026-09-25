use serde_json::{json, Value};
use std::{error::Error, fs, path::PathBuf};

#[path = "paper_checks/collector.rs"]
mod collector;
#[path = "paper_checks/decoder.rs"]
mod decoder;
#[path = "paper_checks/specification.rs"]
mod specification;

type Result<T> = std::result::Result<T, Box<dyn Error>>;

struct Options {
    experiment: String,
    out: PathBuf,
    seed: u64,
    runs: usize,
}

fn parse(args: &[String]) -> Result<Options> {
    let mut options = Options {
        experiment: "all".into(),
        out: "results_checks".into(),
        seed: 20260921,
        runs: 200,
    };
    let mut arguments = args.iter();
    while let Some(argument) = arguments.next() {
        let value = arguments.next().ok_or("missing argument value")?;
        match argument.as_str() {
            "--experiment" => options.experiment = value.clone(),
            "--out" => options.out = value.into(),
            "--seed" => options.seed = value.parse()?,
            "--runs" => options.runs = value.parse()?,
            _ => return Err(format!("unknown argument: {argument}").into()),
        }
    }
    if !["all", "decoder", "specification", "collector"].contains(&options.experiment.as_str()) {
        return Err("use --experiment all|decoder|specification|collector".into());
    }
    if !(1..=100_000).contains(&options.runs) {
        return Err("--runs must be between 1 and 100000".into());
    }
    Ok(options)
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.iter().any(|arg| arg == "--help" || arg == "-h") {
        println!(
            "Usage: paper_checks [--experiment all|decoder|specification|collector] \
             [--out NEW_DIRECTORY] [--seed 20260921] [--runs 200]\n\
             decoder: Table 8 and Appendix E.2 correctness/rank checks.\n\
             specification: Appendix E.4 finite-field enumeration.\n\
             collector: Table 9 simulation; --runs sets trials per pattern/mode.\n\
             These execute new computations without archived measurements or hash manifests."
        );
        return Ok(());
    }
    let options = parse(&args)?;
    fs::create_dir(&options.out)?;
    let mut report = json!({
        "status": "running",
        "experiment": options.experiment,
        "seed": options.seed,
        "collector_runs": options.runs,
        "results": {},
        "sampling": "New deterministic runs; the manuscript does not specify the original random seeds or generator."
    });
    let report_path = options.out.join("checks.json");
    fs::write(&report_path, serde_json::to_vec_pretty(&report)?)?;
    for experiment in ["decoder", "specification", "collector"] {
        if options.experiment != "all" && options.experiment != experiment {
            continue;
        }
        eprintln!("Running {experiment} ...");
        let result: Result<Value> = match experiment {
            "decoder" => decoder::run(&options.out, options.seed),
            "specification" => specification::run(&options.out, options.seed),
            "collector" => collector::run(&options.out, options.seed, options.runs),
            _ => unreachable!(),
        };
        match result {
            Ok(value) => {
                report["results"][experiment] = value;
                fs::write(&report_path, serde_json::to_vec_pretty(&report)?)?;
                println!("{experiment}: complete");
            }
            Err(error) => {
                report["status"] = json!("failed");
                report["failed_experiment"] = json!(experiment);
                report["error"] = json!(error.to_string());
                fs::write(&report_path, serde_json::to_vec_pretty(&report)?)?;
                return Err(error);
            }
        }
    }
    report["status"] = json!("complete");
    fs::write(report_path, serde_json::to_vec_pretty(&report)?)?;
    println!("Results: {}", options.out.display());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::parse;

    #[test]
    fn rejects_bad_selection_counts_and_incomplete_arguments() {
        for args in [
            vec!["--experiment", "unknown"],
            vec!["--runs", "0"],
            vec!["--runs", "100001"],
            vec!["--seed", "no"],
            vec!["--out"],
        ] {
            let args: Vec<String> = args.into_iter().map(String::from).collect();
            assert!(parse(&args).is_err());
        }
    }
}
