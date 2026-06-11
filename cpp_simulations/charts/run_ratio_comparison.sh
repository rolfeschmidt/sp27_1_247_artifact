#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
BUILD_DIR=${BUILD_DIR:-"$SCRIPT_DIR/../build"}
BIN=${BIN:-"$BUILD_DIR/agg_unikem_experiment"}
DATA_DIR=${DATA_DIR:-"$SCRIPT_DIR/data"}
PLOT_DIR=${PLOT_DIR:-"$SCRIPT_DIR/out"}
TICKS=${TICKS:-100000}
SEED=${SEED:-0}

protocols=(
  "agg-uni-kem"
  "agg-rukem"
  "opp-uni-kem"
  "opp-rkem"
)

ratios=(
  "10:10"
  "3:3"
  "1:1"
  "0.33:0p3"
  "0.1:0p1"
)

mkdir -p "$BUILD_DIR" "$DATA_DIR" "$PLOT_DIR"
cmake -S "$SCRIPT_DIR/.." -B "$BUILD_DIR"
cmake --build "$BUILD_DIR" --target agg_unikem_experiment

for ratio_pair in "${ratios[@]}"; do
  ratio=${ratio_pair%%:*}
  slug=${ratio_pair##*:}

  for protocol in "${protocols[@]}"; do
    base="$DATA_DIR/ratio_${slug}_${protocol}"
    echo "Running protocol=$protocol ratio=$ratio ticks=$TICKS"
    "$BIN" \
      --protocol "$protocol" \
      --traffic ratio \
      --ratio "$ratio" \
      --ticks "$TICKS" \
      --seed "$SEED" \
      --hist-output "${base}_hist.csv" \
      --stats-output "${base}_stats.csv"
  done

  gnuplot \
    -e "data_dir='${DATA_DIR}'" \
    -e "plot_dir='${PLOT_DIR}'" \
    -e "ratio_slug='${slug}'" \
    -e "ratio_label='${ratio}'" \
    "$SCRIPT_DIR/ratio_comparison_hist.gp"
  gnuplot \
    -e "data_dir='${DATA_DIR}'" \
    -e "plot_dir='${PLOT_DIR}'" \
    -e "ratio_slug='${slug}'" \
    -e "ratio_label='${ratio}'" \
    "$SCRIPT_DIR/ratio_comparison_cdf.gp"

  party_col=4
  if [[ "$ratio" == 0.* ]]; then
    party_col=5
  fi

  gnuplot \
    -e "data_dir='${DATA_DIR}'" \
    -e "plot_dir='${PLOT_DIR}'" \
    -e "ratio_slug='${slug}'" \
    -e "ratio_label='${ratio}'" \
    -e "party_col=${party_col}" \
    "$SCRIPT_DIR/ratio_fast_sender_cdf.gp"
done

echo "Wrote data to $DATA_DIR"
echo "Wrote plots to $PLOT_DIR"
