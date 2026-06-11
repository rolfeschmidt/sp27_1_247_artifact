#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
RESULTS_DIR=${RESULTS_DIR:-"$SCRIPT_DIR/results"}

TICKS=${TICKS:-100000}
SEED=${SEED:-0}
JOBS=${JOBS:-1}

mkdir -p "$RESULTS_DIR"

export TICKS
export SEED
export JOBS
export DATA_DIR="$RESULTS_DIR/paper-data"
export PLOT_DIR="$RESULTS_DIR/paper-plots"
export LOG_DIR="$RESULTS_DIR/logs"
export EXPERIMENT_NUMBERS_OUT="$RESULTS_DIR/experiment_numbers.tex"
export EXPERIMENT_TABLE_OUT="$RESULTS_DIR/experiment_numbers_table.tex"
export GENERATE_NUMBERS=1
export GENERATE_TABLE=1

"$SCRIPT_DIR/cpp_simulations/charts/run_improvement_experiments.sh"

if command -v latexmk >/dev/null 2>&1; then
  latexmk -pdf -interaction=nonstopmode -halt-on-error \
    -outdir="$RESULTS_DIR" \
    "$EXPERIMENT_TABLE_OUT"
  echo "Wrote $RESULTS_DIR/experiment_numbers_table.pdf"
else
  echo "latexmk not found; wrote TeX table but did not build PDF"
fi
