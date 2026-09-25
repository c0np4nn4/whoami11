#!/usr/bin/env python3
import argparse
import csv
import hashlib
import json
from pathlib import Path
import statistics


ROOT = Path(__file__).resolve().parents[1]
PARAMS = {"ell": 123, "m": 1024, "r": 768, "a": 82, "b": 0}
SCHEMES = ("lrdas_a", "product_a", "lrdas_b", "product_b")


def require(condition, message):
    if not condition:
        raise ValueError(message)


def parse_json(text):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, f"duplicate JSON key: {key}")
            result[key] = value
        return result

    def bad_constant(value):
        raise ValueError(f"non-finite JSON constant: {value}")

    return json.loads(text, object_pairs_hook=unique, parse_constant=bad_constant)


def load_json(path):
    return parse_json(path.read_text(encoding="utf-8"))


def verify_source(root, environment):
    archive = root / "provenance/tradeoffs-paper-source"
    manifest = load_json(archive / "SOURCE_MANIFEST.json")
    require(manifest == environment["source"], "archived source manifest differs from environment")
    files = manifest["files"]
    require(bool(files), "empty source manifest")
    digest = hashlib.sha256(json.dumps(files, sort_keys=True).encode()).hexdigest()
    require(digest == manifest["sha256"], "invalid source manifest hash")
    stripped = load_json(archive / "COMMENT_STRIPPED_MANIFEST.json")
    require(stripped["original_source_sha256"] == digest, "original source digest mismatch")
    require(set(stripped["files"]) == set(files), "comment-stripped source file set mismatch")
    stripped_digest = hashlib.sha256(json.dumps(stripped["files"], sort_keys=True).encode()).hexdigest()
    require(stripped_digest == stripped["sha256"], "invalid comment-stripped source manifest hash")
    for name, expected in stripped["files"].items():
        path = archive / name
        require(path.resolve().is_relative_to(archive.resolve()), "source path escapes archive")
        require(hashlib.sha256(path.read_bytes()).hexdigest() == expected,
                f"comment-stripped source hash mismatch: {name}")
    return digest, stripped_digest


def workload(row):
    return row["scheme"], row["operation"], row["input_size"], row["cache_policy"]


def load_runs(folder, params, expected, *, environment=None):
    require({p.name for p in folder.glob("run-*.jsonl")} ==
            {f"run-{i}.jsonl" for i in range(3)}, f"expected three sample files: {folder}")
    require({p.name for p in folder.glob("run-*.status.json")} ==
            {f"run-{i}.status.json" for i in range(3)}, f"expected three status files: {folder}")
    manifests, means = [], {key: [] for key in expected}
    reference = None
    for process in range(3):
        label = f"{folder.name}/run-{process}"
        status = load_json(folder / f"run-{process}.status.json")
        require(status["status"] == "complete" and status["error"] is None,
                f"incomplete process: {label}")
        require(status["schema_version"] == 1 and status["process_run_id"] == process,
                f"invalid process identity: {label}")
        config = status["config"]
        require(config["params"] == params, f"unexpected paper parameters: {label}")
        require(config["samples"] == 10 and config["slow_samples"] == 1,
                f"unexpected sample configuration: {label}")
        require(config["seed"] == 20260921 + process, f"unexpected seed: {label}")
        base = {key: value for key, value in config.items() if key != "seed"}
        require(reference is None or base == reference, f"mixed configurations: {label}")
        reference = base
        if environment is not None:
            require(status["environment"] == environment and status["filter"] == "" and
                    config["suite"] == "tradeoffs" and config["name"] == "tradeoffs-reference",
                    f"inconsistent tradeoffs environment/config: {label}")
        else:
            require(status["table"] == 3 and config["name"] == "paper-reference" and
                    config["reconstruction_params"] == [], f"unexpected reconstruction config: {label}")
            stored_config = load_json(folder / "config.json")
            require(stored_config == dict(config, seed=20260921), f"config file mismatch: {label}")
        lines = (folder / f"run-{process}.jsonl").read_text(encoding="utf-8").splitlines()
        require(len(lines) == status["rows"], f"row count mismatch: {label}")
        seen, selected = set(), {key: {} for key in expected}
        for line in lines:
            row = parse_json(line)
            key = workload(row)
            for field in ("iterations", "elapsed_ns", "input_size", "sample_id", "process_run_id"):
                require(type(row[field]) is int and row[field] >= 0,
                        f"invalid {field}: {label}")
            require(row["iterations"] > 0 and row["elapsed_ns"] > 0,
                    f"nonpositive elapsed time/iterations: {label}")
            require(row["schema_version"] == 1 and row["threads"] == 1 and
                    row["backend"] == "arkworks-0.4" and row["status"] == "ok" and
                    row["measurement_kind"] == "measured" and
                    row["timing_scope"] == "wall_clock_library_or_role_as_documented",
                    f"invalid measured sample: {label}")
            require(row["process_run_id"] == process and row["seed"] == config["seed"] and
                    row["profile"] == config["name"] and
                    row["run_id"] == f"{config['name']}-{process}" and
                    row["fixture_id"] == f"chacha20-v1-{config['seed']}" and
                    row["workload_id"] == "/".join(map(str, key)),
                    f"inconsistent sample identity: {label}")
            identity = key, row["sample_id"]
            require(identity not in seen, f"duplicate sample: {label}")
            seen.add(identity)
            if key in selected:
                selected[key][row["sample_id"]] = row["elapsed_ns"] / row["iterations"] / 1e6
        for key, count in expected.items():
            require(set(selected[key]) == set(range(count)), f"missing/invalid target samples: {label}, {key}")
            means[key].append(statistics.mean(selected[key].values()))
        manifests.append(status)
    return manifests, means


def role_value(manifests, scheme, field):
    values = []
    for status in manifests:
        roles = [role for role in status["roles"] if role.get("variant") == scheme]
        require(len(roles) == 1, f"missing/duplicate role: {scheme}")
        value = roles[0][field]
        require(type(value) is int and value > 0, f"invalid role field: {scheme}/{field}")
        values.append(value)
    require(len(set(values)) == 1, f"inconsistent role field: {scheme}/{field}")
    return values[0]


def aggregate(root):
    tradeoffs = root / "results/raw/tradeoffs-paper"
    environment = load_json(tradeoffs / "environment.json")
    require(environment["runs_requested"] == 3 and environment["filter"] == "",
            "expected three unfiltered tradeoffs processes")
    source_hash, stripped_source_hash = verify_source(root, environment)
    expected = {}
    for scheme in SCHEMES:
        queries = 218 if scheme.startswith("lrdas") else 991
        expected[scheme, "variant_header_commit", 82, "public_srs"] = 1
        expected[scheme, "variant_light_client", queries, "cold"] = 10
    manifests, process_means = load_runs(tradeoffs, PARAMS, expected, environment=environment)
    headers, srs, commit, client = [], [], [], []
    for scheme in SCHEMES:
        queries = 218 if scheme.startswith("lrdas") else 991
        require(role_value(manifests, scheme, "queries") == queries, "unexpected query count")
        headers.append(role_value(manifests, scheme, "header_bytes"))
        srs.append(role_value(manifests, scheme, "public_g1_bytes"))
        commit.append(statistics.mean(process_means[scheme, "variant_header_commit", 82, "public_srs"]))
        client.append(statistics.mean(process_means[scheme, "variant_light_client", queries, "cold"]))
    require(headers == [3936, 3936, 7872, 7872] and srs == [36864, 36864, 4018176, 4018176],
            "unexpected serialized sizes")
    reconstruction = {}
    reconstruction_means = {}
    for case, m in enumerate((512, 1024, 2048), 1):
        params = dict(PARAMS, m=m, r=3 * m // 4)
        survivors = params["ell"] * (params["r"] - 1)
        expected = {(scheme, "diagonal_full_decode", survivors, "accepted_values"): 1
                    for scheme in ("lrdas_a", "product_a")}
        folder = root / f"results_table3/table3-case-{case}"
        statuses, means = load_runs(folder, params, expected)
        for status in statuses:
            roles = status["roles"]
            require(len(roles) == 2 and {r["reconstruction_scheme"] for r in roles} ==
                    {"lrdas_a", "product_a"}, "invalid reconstruction roles")
            for role in roles:
                require(role["survivors"] == survivors and role["survivors_per_group"] == params["r"] - 1 and
                        role["erased_per_group"] == m - params["r"] + 1 and
                        role["input_verification_excluded"] is True and
                        role["outputs"] == ["message", "codeword", "local_polynomials"],
                        "unexpected reconstruction timing boundary/pattern")
        reconstruction_means[str(m)] = {key[0]: values for key, values in means.items()}
        reconstruction[m] = [statistics.mean(means[scheme, "diagonal_full_decode", survivors, "accepted_values"])
                             for scheme in ("lrdas_a", "product_a")]
    timing = lambda values: [f"{value:.1f}" for value in values]
    table2 = [
        ["Operation", "Unit", "LR-DAS", "Product", "Evidence"],
        ["Commitment generation", "ms", *timing(commit[:2]), "measured"],
        ["Unbatched client verification", "ms", *timing(client[:2]), "measured"],
        ["Full reconstruction, pattern of Proposition 7", "ms", *timing(reconstruction[1024]), "measured"],
        ["Batched check (10)", "MSM terms, pairings", f"{82 + 2 * 218 + 1}, 2", f"{82 + 2 * 991 + 1}, 2", "analytic"],
    ]
    table7 = [
        ["Operation", "Unit", "Profile A LR-DAS", "Profile A Product", "Profile B LR-DAS", "Profile B Product"],
        ["Commitment generation", "ms", *timing(commit)],
        ["Unbatched client verification", "ms", *timing(client)],
        ["Commitment size", "B", *map(str, headers)],
        ["G1 reference-string size", "B", *map(str, srs)],
        *[[f"Reconstruction, m = {m}", "ms", *timing(reconstruction[m]), "", ""] for m in reconstruction],
    ]
    summary = {
        "aggregation": "equal mean of three independent process means; milliseconds per iteration",
        "tradeoffs_source_sha256": source_hash,
        "tradeoffs_comment_stripped_source_sha256": stripped_source_hash,
        "tradeoffs_source_provenance": "Archived source comments were removed; original measurement hashes are retained separately from the current source hashes.",
        "tradeoffs_process_means_ms": {"/".join(map(str, key)): values for key, values in process_means.items()},
        "reconstruction_process_means_ms": reconstruction_means,
        "reconstruction_provenance": "Original reconstruction statuses contain no source/environment hash.",
        "batched_check": "Analytic a + 2N + 1 MSM terms and 2 pairings; no measured batched runtime.",
    }
    return table2, table7, summary


def write_results(root, output):
    table2, table7, summary = aggregate(root)
    output.mkdir(parents=True, exist_ok=False)
    for name, rows in (("table2.csv", table2), ("table7.csv", table7)):
        with (output / name).open("x", newline="", encoding="utf-8") as stream:
            csv.writer(stream).writerows(rows)
    (output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")


def main():
    parser = argparse.ArgumentParser(description="Rebuild PDF Tables 2 and 7 from archived measurements.")
    parser.add_argument("--root", type=Path, default=ROOT, help="repository/archive root")
    parser.add_argument("--output", type=Path, default=ROOT / "dist/paper", help="new output directory (must not exist)")
    args = parser.parse_args()
    try:
        write_results(args.root, args.output)
    except (OSError, ValueError, KeyError, TypeError) as error:
        parser.exit(1, f"paper_results: {error}\n")
    print(f"Validated archived data; wrote PDF Tables 2 and 7 to {args.output}")


if __name__ == "__main__":
    main()
