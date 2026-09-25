use lrdas_artifact::fixture;
use rand::{seq::SliceRandom, Rng};
use serde::Serialize;
use serde_json::{json, Value};
use std::{error::Error, fs, path::Path};

const GROUPS: usize = 123;
const POSITIONS: usize = 1024;
const THRESHOLD: usize = 768;
const TARGET: usize = 82;
const BUDGETS: [usize; 3] = [50_000, 100_000, 126_000];

#[derive(Clone, Copy)]
enum Pattern {
    S1,
    S2,
    S3,
}

impl Pattern {
    fn name(self) -> &'static str {
        match self {
            Self::S1 => "S1",
            Self::S2 => "S2",
            Self::S3 => "S3",
        }
    }

    fn availability(self, rng: &mut impl Rng) -> Vec<Vec<bool>> {
        (0..GROUPS)
            .map(|group| match self {
                Self::S1 => vec![group >= 41; POSITIONS],
                Self::S2 => {
                    let missing = if group < 82 { 200 } else { 300 };
                    let mut positions = vec![true; POSITIONS];
                    positions[..missing].fill(false);
                    positions.shuffle(rng);
                    positions
                }
                Self::S3 => (0..POSITIONS).map(|_| !rng.gen_bool(0.2)).collect(),
            })
            .collect()
    }

    fn paper_values(self) -> ([usize; 3], [f64; 3]) {
        match self {
            Self::S1 => ([73_381, 72_742, 73_513], [55.4, 82.0, 82.0]),
            Self::S2 => ([113_760, 110_493, 114_381], [35.7, 71.5, 82.0]),
            Self::S3 => ([78_722, 78_284, 79_821], [51.8, 103.8, 123.0]),
        }
    }
}

#[derive(Debug, Serialize)]
struct Counts {
    queries: usize,
    accepted: usize,
    failed: usize,
    certified_groups: usize,
    rejected_groups: usize,
    touched_groups: usize,
    recoverable_groups: usize,
    missing_positions: usize,
    reached_target: bool,
    stop_reason: &'static str,
}

fn simulate(
    availability: &[Vec<bool>],
    threshold: usize,
    target: usize,
    budget: Option<usize>,
    rng: &mut impl Rng,
) -> Counts {
    let mut result = Counts {
        queries: 0,
        accepted: 0,
        failed: 0,
        certified_groups: 0,
        rejected_groups: 0,
        touched_groups: 0,
        recoverable_groups: availability
            .iter()
            .filter(|group| group.iter().filter(|&&v| v).count() >= threshold)
            .count(),
        missing_positions: availability.iter().flatten().filter(|&&v| !v).count(),
        reached_target: target == 0,
        stop_reason: "groups_exhausted",
    };
    if target == 0 && budget.is_none() {
        result.stop_reason = "recovery_target";
        return result;
    }
    let mut groups: Vec<usize> = (0..availability.len()).collect();
    groups.shuffle(rng);
    for group in groups {
        if budget.is_some_and(|limit| result.queries >= limit) {
            result.stop_reason = "query_budget";
            return result;
        }
        let available = &availability[group];
        assert!(threshold > 0 && threshold <= available.len());
        let failure_limit = available.len() - threshold + 1;
        let mut positions: Vec<usize> = (0..available.len()).collect();
        let mut accepted = 0;
        let mut failed = 0;
        result.touched_groups += 1;
        for index in 0..positions.len() {
            if budget.is_some_and(|limit| result.queries >= limit) {
                result.stop_reason = "query_budget";
                return result;
            }
            let next = rng.gen_range(index..positions.len());
            positions.swap(index, next);
            result.queries += 1;
            if available[positions[index]] {
                accepted += 1;
                result.accepted += 1;
            } else {
                failed += 1;
                result.failed += 1;
            }
            if accepted == threshold {
                result.certified_groups += 1;
                result.reached_target = result.certified_groups >= target;
                if result.reached_target && budget.is_none() {
                    result.stop_reason = "recovery_target";
                    return result;
                }
                break;
            }
            if failed == failure_limit {
                result.rejected_groups += 1;
                break;
            }
        }
    }
    result
}

#[derive(Serialize)]
struct Trial {
    pattern: &'static str,
    trial: usize,
    mode: &'static str,
    budget: Option<usize>,
    rng_stream: String,
    #[serde(flatten)]
    counts: Counts,
}

#[derive(Serialize)]
struct Stats {
    count: usize,
    mean: Option<f64>,
    min: Option<usize>,
    max: Option<usize>,
    standard_error: Option<f64>,
}

fn stats(values: &[usize]) -> Stats {
    let count = values.len();
    let mean =
        (!values.is_empty()).then(|| values.iter().map(|&v| v as f64).sum::<f64>() / count as f64);
    let standard_error = if count > 1 {
        let mean = mean.unwrap();
        let squared = values
            .iter()
            .map(|&v| (v as f64 - mean).powi(2))
            .sum::<f64>();
        Some((squared / ((count - 1) * count) as f64).sqrt())
    } else {
        None
    };
    Stats {
        count,
        mean,
        min: values.iter().copied().min(),
        max: values.iter().copied().max(),
        standard_error,
    }
}

fn csv_number(value: Option<f64>) -> String {
    value.map(|v| format!("{v:.6}")).unwrap_or_default()
}

fn execute(pattern: Pattern, seed: u64, trial: usize, budget: Option<usize>) -> Trial {
    let mode = if budget.is_some() {
        "coverage"
    } else {
        "recovery"
    };
    let label = format!(
        "paper-collector/{}/{trial}/{mode}/{}",
        pattern.name(),
        budget
            .map(|b| b.to_string())
            .unwrap_or_else(|| "none".into())
    );
    let availability = pattern.availability(&mut fixture::rng(seed, &format!("{label}/missing")));
    let counts = simulate(
        &availability,
        THRESHOLD,
        TARGET,
        budget,
        &mut fixture::rng(seed, &format!("{label}/queries")),
    );
    Trial {
        pattern: pattern.name(),
        trial,
        mode,
        budget,
        rng_stream: label,
        counts,
    }
}

pub fn run(out: &Path, seed: u64, runs: usize) -> Result<Value, Box<dyn Error>> {
    if runs == 0 {
        return Err("collector runs must be positive".into());
    }
    fs::create_dir_all(out)?;
    let mut raw = Vec::with_capacity(runs * 12);
    let mut summaries = Vec::new();
    let mut csv = String::from(
        "pattern,runs,recovery_successes,recovery_exhausted,queries_mean,queries_min,queries_max,queries_standard_error,certified_50000_mean,certified_100000_mean,certified_126000_mean,paper_queries_mean,paper_queries_min,paper_queries_max,paper_certified_50000_mean,paper_certified_100000_mean,paper_certified_126000_mean\n",
    );
    for pattern in [Pattern::S1, Pattern::S2, Pattern::S3] {
        let mut recovery_values = Vec::with_capacity(runs);
        let mut recovery_exhausted = 0;
        let mut coverage_values: [Vec<usize>; 3] =
            std::array::from_fn(|_| Vec::with_capacity(runs));
        for trial in 0..runs {
            let recovery = execute(pattern, seed, trial, None);
            if recovery.counts.reached_target {
                recovery_values.push(recovery.counts.queries);
            } else {
                recovery_exhausted += 1;
            }
            raw.push(recovery);
            for (index, budget) in BUDGETS.iter().enumerate() {
                let coverage = execute(pattern, seed, trial, Some(*budget));
                coverage_values[index].push(coverage.counts.certified_groups);
                raw.push(coverage);
            }
        }
        let recovery = stats(&recovery_values);
        let coverage: [Stats; 3] = std::array::from_fn(|index| stats(&coverage_values[index]));
        let (paper_queries, paper_coverage) = pattern.paper_values();
        let row = vec![
            pattern.name().to_string(),
            runs.to_string(),
            recovery.count.to_string(),
            recovery_exhausted.to_string(),
            csv_number(recovery.mean),
            recovery.min.map(|v| v.to_string()).unwrap_or_default(),
            recovery.max.map(|v| v.to_string()).unwrap_or_default(),
            csv_number(recovery.standard_error),
            csv_number(coverage[0].mean),
            csv_number(coverage[1].mean),
            csv_number(coverage[2].mean),
            paper_queries[0].to_string(),
            paper_queries[1].to_string(),
            paper_queries[2].to_string(),
            paper_coverage[0].to_string(),
            paper_coverage[1].to_string(),
            paper_coverage[2].to_string(),
        ];
        csv.push_str(&row.join(","));
        csv.push('\n');
        summaries.push(json!({
            "pattern": pattern.name(),
            "recovery": recovery,
            "recovery_exhausted": recovery_exhausted,
            "coverage": BUDGETS.iter().zip(coverage).map(|(budget, stats)| {
                json!({"budget": budget, "certified_groups": stats})
            }).collect::<Vec<_>>(),
            "paper_reference": {
                "queries_mean": paper_queries[0],
                "queries_min": paper_queries[1],
                "queries_max": paper_queries[2],
                "coverage_mean": paper_coverage
            }
        }));
    }
    let summary = json!({
        "experiment": "Appendix F / Table 9 sequential collector policy",
        "seed": seed,
        "runs_per_pattern_and_mode": runs,
        "groups": GROUPS,
        "positions_per_group": POSITIONS,
        "accepted_to_certify": THRESHOLD,
        "failed_to_reject": POSITIONS - THRESHOLD + 1,
        "recovery_target": TARGET,
        "coverage_budgets": BUDGETS,
        "rng": "ChaCha20 with SHA-256 domain separation via fixture::rng",
        "mode_streams": "Independent missing patterns and query streams for each pattern, trial, mode and coverage budget",
        "paper_comparison": "The paper does not specify its RNG or seed. These are fresh simulations; paper_reference fields are comparison data only and do not enter any simulation.",
        "query_model": "Each available coordinate supplies an accepted opening; each missing coordinate counts as a failed opening. This is a collection-policy simulation, without cryptographic verification timings.",
        "coverage_rule": "Count only certified groups; stop at the query budget or when all groups are decided",
        "recovery_statistics": "Successful trials only, with exhausted trials reported separately and never resampled",
        "analytical_reference": {
            "s1_expected_queries": 82.0 * 768.0 + (41.0 * 82.0 / 83.0) * 257.0,
            "s1_maximum_queries": 82 * 768 + 41 * 257,
            "s3_approximate_queries": (82.0 * 768.0) / 0.8
        },
        "patterns": summaries,
    });
    fs::write(out.join("table9.csv"), csv)?;
    let mut full = summary.clone();
    full["trials"] = serde_json::to_value(&raw)?;
    fs::write(
        out.join("collector.json"),
        serde_json::to_vec_pretty(&full)?,
    )?;
    Ok(summary)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn budget_counts_only_completed_certifications() {
        let groups = vec![vec![true; 4], vec![true; 4]];
        for (budget, queries, certified) in [
            (0, 0, 0),
            (2, 2, 0),
            (3, 3, 1),
            (4, 4, 1),
            (6, 6, 2),
            (8, 6, 2),
        ] {
            let result = simulate(&groups, 3, 1, Some(budget), &mut fixture::rng(1, "budget"));
            assert_eq!(result.queries, queries);
            assert_eq!(result.certified_groups, certified);
            assert_eq!(result.failed, 0);
        }
    }

    #[test]
    fn group_decisions_use_the_two_exact_thresholds() {
        let groups = vec![vec![true; 8], vec![false; 8]];
        let result = simulate(&groups, 5, 2, Some(100), &mut fixture::rng(2, "thresholds"));
        assert_eq!(result.accepted, 5);
        assert_eq!(result.failed, 4);
        assert_eq!(result.queries, 9);
        assert_eq!(result.certified_groups, 1);
        assert_eq!(result.rejected_groups, 1);
    }

    #[test]
    fn without_replacement_preserves_every_groups_recoverability() {
        let groups = vec![
            vec![true, false, true, false, true, false, true, true],
            vec![false, true, false, true, false, true, false, false],
        ];
        for seed in 0..64 {
            let result = simulate(
                &groups,
                5,
                2,
                Some(100),
                &mut fixture::rng(seed, "replacement"),
            );
            assert_eq!(result.certified_groups, 1);
            assert_eq!(result.rejected_groups, 1);
            assert_eq!(result.recoverable_groups, 1);
            assert!(result.queries <= 16);
            assert!(result.accepted <= 8);
            assert!(result.failed <= 8);
            assert_eq!(result.queries, result.accepted + result.failed);
        }
    }

    #[test]
    fn unreachable_recovery_exhausts_groups_without_resampling() {
        let result = simulate(
            &[vec![true; 4], vec![false; 4]],
            3,
            2,
            None,
            &mut fixture::rng(3, "exhaustion"),
        );
        assert!(!result.reached_target);
        assert_eq!(result.stop_reason, "groups_exhausted");
        assert_eq!(result.certified_groups, 1);
        assert_eq!(result.touched_groups, 2);
        assert_eq!(result.queries, 5);
    }

    #[test]
    fn recovery_stops_at_target_and_coverage_continues() {
        let groups = vec![vec![true; 4]; 3];
        let recovery = simulate(&groups, 3, 1, None, &mut fixture::rng(4, "modes"));
        let coverage = simulate(&groups, 3, 1, Some(9), &mut fixture::rng(4, "modes"));
        assert_eq!(recovery.queries, 3);
        assert_eq!(recovery.certified_groups, 1);
        assert_eq!(recovery.stop_reason, "recovery_target");
        assert_eq!(coverage.queries, 9);
        assert_eq!(coverage.certified_groups, 3);
    }
}
