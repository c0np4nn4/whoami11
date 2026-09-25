# Reproduce the paper experiments

Run from this directory. Each output directory must be new.

## Tables 2 and 7: performance measurements

```sh
cargo run --locked --release --bin bench -- \
  --table all --config reference.json --out results_runtime --runs 3
```

- `results_runtime/table2.csv`: commitment generation, unbatched client verification, and commitment sizes.
- `results_runtime/table3.csv`: full reconstruction for group sizes 512, 1024, and 2048.

## Table 8, Appendix E.4, and Table 9

```sh
cargo run --locked --release --bin paper_checks -- \
  --experiment all --out results_checks --seed 20260921 --runs 200
```

- `results_checks/table8.csv`, `results_checks/decoder.json`: structured decoding and reference-scale rank/recovery checks (Table 8, Appendix E.2).
- `results_checks/specification.json`: 5,791 specification cases and mutation checks (Appendix E.4).
- `results_checks/table9.csv`: collector query counts and coverage, 200 trials per pattern and mode (Table 9).
