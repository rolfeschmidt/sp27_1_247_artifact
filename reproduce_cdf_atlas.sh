#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
ATLAS_DIR=${ATLAS_DIR:-"$SCRIPT_DIR/results/cdf-atlas"}

TICKS=${TICKS:-100000}
SEED=${SEED:-0}
JOBS=${JOBS:-1}

export ATLAS_DIR
export DATA_DIR="${DATA_DIR:-"$ATLAS_DIR/data"}"
export PLOT_DIR="${PLOT_DIR:-"$ATLAS_DIR/plots"}"
export ATLAS_TEX="${ATLAS_TEX:-"$ATLAS_DIR/cdf_atlas.tex"}"
export TICKS
export SEED
export JOBS

"$SCRIPT_DIR/cpp_simulations/charts/run_cdf_atlas.sh"

if command -v latexmk >/dev/null 2>&1; then
  (
    cd "$ATLAS_DIR"
    latexmk -pdf -interaction=nonstopmode -halt-on-error cdf_atlas.tex
  )
  echo "Wrote $ATLAS_DIR/cdf_atlas.pdf"
else
  echo "latexmk not found; wrote atlas TeX and plots but did not build PDF"
fi
