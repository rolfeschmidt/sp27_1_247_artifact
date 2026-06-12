# SP 2027 Paper 247 Artifact

This repository is the standalone artifact for reproducing and checking the
paper's experiment outputs. It contains:

1. `cpp_simulations/`: C++ secure-messaging simulations for the experiment
   values and CDF atlas.
2. `lattice_estimator/`: UKatana parameter and lattice-estimator analysis.
3. `additional_text/`: reserved for proof material or other supplemental text.
4. `results/`: reference TeX/PDF products generated from the artifact.

The generated CSVs, plots, logs, and build directories are intentionally not
included. Reviewers should regenerate them locally and compare the resulting
TeX/PDF products against `results/`.

## Mapping to the Paper

The defaults in both scripts (`TICKS=100000`, `SEED=0`) are exactly the settings
used for the paper, and every run is deterministic for a fixed seed, so a
reproduction matches the paper's values exactly (not just approximately). The
reference products committed under `results/` were generated with these defaults;
regenerate and diff against them.

| Paper item | Produced by | Output to compare |
|---|---|---|
| Experiment numbers (the `\Exp…` macros / main-text means) | `./reproduce_paper_numbers.sh` | `results/experiment_numbers.tex`, `results/experiment_numbers_table.{tex,pdf}` |
| Fig. *Aggressive improvement caps* | `./reproduce_paper_numbers.sh` | `results/paper-plots/aggressive_improvement_caps.png` |
| Fig. *Agg-RUKEM vs Agg-UniKEM trade-off* | `./reproduce_paper_numbers.sh` | `results/paper-plots/aggrukem_vs_aggunikem_tradeoff.png` |
| Fig. *VMS CDF at 10:1* | `./reproduce_cdf_atlas.sh` | `results/cdf-atlas/plots/ratio_10_cdf.png` |
| Full per-ratio CDF atlas (appendix) | `./reproduce_cdf_atlas.sh` | `results/cdf-atlas/cdf_atlas.pdf` |
| Setup: NIST-L3 security level and key/ciphertext sizes (the chunk counts) | `lattice_estimator/rukem_params.py` | console tables (see `lattice_estimator/README.md`) |

The single 10:1 CDF figure (`ratio_10_cdf.png`) is one of the per-ratio plots the
atlas produces; to regenerate just that figure quickly, restrict the ratio:

```sh
RATIOS="10" ./reproduce_cdf_atlas.sh
```

### Expected headline values (`TICKS=100000`, `SEED=0`)

| Quantity | Value |
|---|---|
| Agg-UniKEM fast-party gain @ 10:1 / 15:1 / 20:1 | 2.03× / 2.18× / 2.25× |
| Agg-RUKEM fast-party gain over Opp-RKEM @ 10:1 | 6.50× |
| Agg-RUKEM fast-party gain over Agg-UniKEM @ 10:1 | 2.71× |
| Opp-UniKEM / Agg-UniKEM fast-party mean @ 10:1 | 584.0 / 287.1 |
| Opp-RKEM / Agg-RUKEM fast-party mean @ 10:1 | 688.7 / 106.0 |
| Agg-RUKEM slow-party mean @ 10:1 | 691.4 |

The full set is in `results/experiment_numbers_table.tex`.

### Runtime

`reproduce_paper_numbers.sh` runs 20 ratios × 4 protocols (80 simulations);
`reproduce_cdf_atlas.sh` runs 22 ratios × 4 protocols. Each simulation is on the
order of ~15 s single-threaded at the default tick count, so set `JOBS` to
parallelize (e.g. `JOBS=8`) — both complete in a few minutes on a multi-core
machine.

## Prerequisites

For the simulation path:

- CMake
- a C++20 compiler
- `gnuplot`
- optionally `latexmk`, for rebuilding PDFs from generated TeX

For `lattice_estimator/`, see `lattice_estimator/README.md`. That component can
use SageMath directly or the included Nix flake.

## Reproducing Paper Numbers

Run:

```sh
./reproduce_paper_numbers.sh
```

This writes:

```text
results/paper-data/improvement_ratios.csv
results/paper-plots/
results/logs/
results/experiment_numbers.tex
results/experiment_numbers_table.tex
results/experiment_numbers_table.pdf
```

Useful overrides:

```sh
TICKS=1000 ./reproduce_paper_numbers.sh
TICKS=1000 RATIOS="10 15 20" ./reproduce_paper_numbers.sh
TICKS=100000 JOBS=4 ./reproduce_paper_numbers.sh
SEED=7 ./reproduce_paper_numbers.sh
```

Use the small `TICKS` forms only as smoke tests. They are not expected to match
the paper values.

## Reproducing The CDF Atlas

Run:

```sh
./reproduce_cdf_atlas.sh
```

By default this runs ratio traffic for:

```text
0.1 0.33 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20
```

and writes:

```text
results/cdf-atlas/data/
results/cdf-atlas/plots/
results/cdf-atlas/logs/
results/cdf-atlas/cdf_atlas.tex
results/cdf-atlas/cdf_atlas.pdf
```

Useful overrides:

```sh
TICKS=1000 RATIOS="1" ./reproduce_cdf_atlas.sh
TICKS=100000 JOBS=4 ./reproduce_cdf_atlas.sh
SKIP_EXISTING=1 ./reproduce_cdf_atlas.sh
```

## Direct Simulator Use

Build and test the simulator:

```sh
cmake -S cpp_simulations -B cpp_simulations/build
cmake --build cpp_simulations/build
ctest --test-dir cpp_simulations/build --output-on-failure
```

Run one paper protocol:

```sh
cpp_simulations/build/agg_unikem_experiment \
  --protocol agg-rukem \
  --traffic ratio \
  --ratio 10 \
  --ticks 100000 \
  --seed 0 \
  --stats-output results/one-run-stats.csv \
  --hist-output results/one-run-hist.csv
```

The paper protocols are:

```text
opp-uni-kem
opp-rkem
agg-uni-kem
agg-rukem
```

All simulation runs are deterministic for a fixed seed.
