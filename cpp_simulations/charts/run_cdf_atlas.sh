#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
BUILD_DIR=${BUILD_DIR:-"$SCRIPT_DIR/../build"}
BIN=${BIN:-"$BUILD_DIR/agg_unikem_experiment"}
ATLAS_DIR=${ATLAS_DIR:-"$SCRIPT_DIR/../../artifact/results/cdf-atlas"}
DATA_DIR=${DATA_DIR:-"$ATLAS_DIR/data"}
PLOT_DIR=${PLOT_DIR:-"$ATLAS_DIR/plots"}
ATLAS_TEX=${ATLAS_TEX:-"$ATLAS_DIR/cdf_atlas.tex"}
TICKS=${TICKS:-100000}
SEED=${SEED:-0}
JOBS=${JOBS:-1}
LOG_DIR=${LOG_DIR:-"$ATLAS_DIR/logs"}
SKIP_EXISTING=${SKIP_EXISTING:-0}

protocols=(
  "opp-uni-kem"
  "opp-rkem"
  "agg-uni-kem"
  "agg-rukem"
)

if [[ -n "${RATIOS:-}" ]]; then
  read -r -a ratios <<< "$RATIOS"
else
  ratios=(0.1 0.33 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20)
fi

ratio_slug() {
  local ratio=$1
  echo "${ratio//./p}"
}

protocol_title() {
  case "$1" in
    opp-uni-kem) echo "Opp-UniKEM" ;;
    opp-rkem) echo "Opp-RKEM" ;;
    agg-uni-kem) echo "Agg-UniKEM" ;;
    agg-rukem) echo "Agg-RUKEM" ;;
    *) echo "$1" ;;
  esac
}

max_x_for_ratio() {
  local slug=$1
  local paths=()
  for protocol in "${protocols[@]}"; do
    paths+=("$DATA_DIR/ratio_${slug}_${protocol}_hist.csv")
  done
  awk -F, 'NR > 1 && $1 + 0 > max { max = $1 + 0 } END { print max + 0 }' "${paths[@]}"
}

mkdir -p "$BUILD_DIR" "$DATA_DIR" "$PLOT_DIR" "$ATLAS_DIR"
cmake -S "$SCRIPT_DIR/.." -B "$BUILD_DIR"
cmake --build "$BUILD_DIR" --target agg_unikem_experiment

run_case() {
  local ratio=$1
  local protocol=$2
  local slug
  slug=$(ratio_slug "$ratio")
  local base="$DATA_DIR/ratio_${slug}_${protocol}"

  if [[ "$SKIP_EXISTING" == 1 && -s "${base}_hist.csv" && -s "${base}_stats.csv" ]]; then
    echo "Skipping protocol=$protocol ratio=$ratio; output already exists"
    return
  fi

  echo "Running protocol=$protocol ratio=$ratio ticks=$TICKS seed=$SEED"
  "$BIN" \
    --protocol "$protocol" \
    --traffic ratio \
    --ratio "$ratio" \
    --ticks "$TICKS" \
    --seed "$SEED" \
    --hist-output "${base}_hist.csv" \
    --stats-output "${base}_stats.csv"
}

if (( JOBS <= 1 )); then
  for ratio in "${ratios[@]}"; do
    for protocol in "${protocols[@]}"; do
      run_case "$ratio" "$protocol"
    done
  done
else
  mkdir -p "$LOG_DIR"
  pids=()
  labels=()
  for ratio in "${ratios[@]}"; do
    for protocol in "${protocols[@]}"; do
      log="$LOG_DIR/ratio_$(ratio_slug "$ratio")_${protocol}.log"
      echo "Queueing protocol=$protocol ratio=$ratio ticks=$TICKS seed=$SEED log=$log"
      run_case "$ratio" "$protocol" > "$log" 2>&1 &
      pids+=("$!")
      labels+=("protocol=$protocol ratio=$ratio")
      if (( ${#pids[@]} >= JOBS )); then
        wait "${pids[0]}"
        echo "Finished ${labels[0]}"
        pids=("${pids[@]:1}")
        labels=("${labels[@]:1}")
      fi
    done
  done
  while (( ${#pids[@]} > 0 )); do
    wait "${pids[0]}"
    echo "Finished ${labels[0]}"
    pids=("${pids[@]:1}")
    labels=("${labels[@]:1}")
  done
fi

for ratio in "${ratios[@]}"; do
  slug=$(ratio_slug "$ratio")
  x_max=$(max_x_for_ratio "$slug")

  gnuplot \
    -e "data_dir='${DATA_DIR}'" \
    -e "plot_dir='${PLOT_DIR}'" \
    -e "ratio_slug='${slug}'" \
    -e "ratio_label='${ratio}'" \
    -e "x_max=${x_max}" \
    "$SCRIPT_DIR/ratio_comparison_cdf.gp"

  for protocol in "${protocols[@]}"; do
    gnuplot \
      -e "data_dir='${DATA_DIR}'" \
      -e "plot_dir='${PLOT_DIR}'" \
      -e "ratio_slug='${slug}'" \
      -e "ratio_label='${ratio}'" \
      -e "protocol='${protocol}'" \
      -e "protocol_title='$(protocol_title "$protocol")'" \
      -e "x_max=${x_max}" \
      "$SCRIPT_DIR/protocol_party_cdf.gp"
  done
done

graphic_prefix="$PLOT_DIR/"
if [[ "$PLOT_DIR" == "$ATLAS_DIR"/* ]]; then
  graphic_prefix="${PLOT_DIR#$ATLAS_DIR/}/"
fi

{
  echo "\\documentclass{article}"
  echo "\\usepackage[margin=0.65in]{geometry}"
  echo "\\usepackage{graphicx}"
  echo "\\usepackage{booktabs}"
  echo "\\usepackage[T1]{fontenc}"
  echo "\\graphicspath{{${graphic_prefix}}}"
  echo "\\begin{document}"
  echo "\\title{CDF Atlas For Secure-Messaging Simulations}"
  echo "\\author{}"
  echo "\\date{}"
  echo "\\maketitle"
  echo "This atlas contains empirical vulnerable-message-set CDFs for the four protocols analyzed in the paper: Opp-UniKEM, Opp-RKEM, Agg-UniKEM, and Agg-RUKEM. Each simulation uses ratio traffic with Alice:Bob activation ratio \$r:1\$, seed ${SEED}, and ${TICKS} ticks."
  echo
  echo "\\begin{center}"
  echo "\\begin{tabular}{@{}lp{0.72\\linewidth}@{}}"
  echo "\\toprule"
  echo "Field & Value \\\\"
  echo "\\midrule"
  echo "Protocols & Opp-UniKEM, Opp-RKEM, Agg-UniKEM, Agg-RUKEM \\\\"
  echo "Ratios & ${ratios[*]} \\\\"
  echo "Ticks & ${TICKS} \\\\"
  echo "Seed & ${SEED} \\\\"
  echo "\\bottomrule"
  echo "\\end{tabular}"
  echo "\\end{center}"
  echo "\\clearpage"

  for ratio in "${ratios[@]}"; do
    slug=$(ratio_slug "$ratio")
    echo "\\section*{Ratio Traffic: Alice:Bob = ${ratio}:1}"
    echo "\\begin{center}"
    echo "\\includegraphics[width=0.94\\linewidth]{ratio_${slug}_cdf.png}"
    echo "\\end{center}"
    echo
    echo "\\begin{center}"
    echo "\\begin{tabular}{cc}"
    echo "\\includegraphics[width=0.47\\linewidth]{ratio_${slug}_opp-uni-kem_cdf.png} &"
    echo "\\includegraphics[width=0.47\\linewidth]{ratio_${slug}_opp-rkem_cdf.png} \\\\"
    echo "\\includegraphics[width=0.47\\linewidth]{ratio_${slug}_agg-uni-kem_cdf.png} &"
    echo "\\includegraphics[width=0.47\\linewidth]{ratio_${slug}_agg-rukem_cdf.png}"
    echo "\\end{tabular}"
    echo "\\end{center}"
    echo "\\clearpage"
  done

  echo "\\end{document}"
} > "$ATLAS_TEX"

echo "Wrote atlas data to $DATA_DIR"
echo "Wrote atlas plots to $PLOT_DIR"
echo "Wrote atlas TeX to $ATLAS_TEX"
