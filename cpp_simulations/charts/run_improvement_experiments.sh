#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
BUILD_DIR=${BUILD_DIR:-"$SCRIPT_DIR/../build"}
BIN=${BIN:-"$BUILD_DIR/agg_unikem_experiment"}
DATA_DIR=${DATA_DIR:-"$SCRIPT_DIR/data"}
PLOT_DIR=${PLOT_DIR:-"$SCRIPT_DIR/out"}
TICKS=${TICKS:-100000}
SEED=${SEED:-0}
JOBS=${JOBS:-1}
LOG_DIR=${LOG_DIR:-"$DATA_DIR/logs"}
SKIP_EXISTING=${SKIP_EXISTING:-0}
GENERATE_NUMBERS=${GENERATE_NUMBERS:-1}
GENERATE_TABLE=${GENERATE_TABLE:-0}
EXPERIMENT_NUMBERS_OUT=${EXPERIMENT_NUMBERS_OUT:-"$SCRIPT_DIR/../../Input_Section/experiment_numbers.tex"}
EXPERIMENT_TABLE_OUT=${EXPERIMENT_TABLE_OUT:-"$SCRIPT_DIR/../../artifact/results/experiment_numbers_table.tex"}

protocols=(
  "opp-uni-kem"
  "agg-uni-kem"
  "opp-rkem"
  "agg-rukem"
)

if [[ -n "${RATIOS:-}" ]]; then
  read -r -a ratios <<< "$RATIOS"
else
  ratios=(1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20)
fi

mkdir -p "$BUILD_DIR" "$DATA_DIR" "$PLOT_DIR"
cmake -S "$SCRIPT_DIR/.." -B "$BUILD_DIR"
cmake --build "$BUILD_DIR" --target agg_unikem_experiment

run_case() {
  local ratio=$1
  local protocol=$2
  local base="$DATA_DIR/improvement_ratio_${ratio}_${protocol}"

  if [[ "$SKIP_EXISTING" == 1 && -s "${base}_stats.csv" ]]; then
    echo "Skipping protocol=$protocol ratio=$ratio; ${base}_stats.csv exists"
    return
  fi

  echo "Running protocol=$protocol ratio=$ratio ticks=$TICKS seed=$SEED"
  "$BIN" \
    --protocol "$protocol" \
    --traffic ratio \
    --ratio "$ratio" \
    --ticks "$TICKS" \
    --seed "$SEED" \
    --stats-output "${base}_stats.csv"
}

# Compromise model: this experiment samples one Alice and one Bob compromise
# after every simulation tick.  A state-change-only compromise model is a
# plausible alternative, but it can underweight slow-party exposure and make the
# aggressive protocols look artificially better.
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
      log="$LOG_DIR/improvement_ratio_${ratio}_${protocol}.log"
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

summary_csv="$DATA_DIR/improvement_ratios.csv"
{
  echo "ratio,opp_unikem_total_mean,opp_unikem_fast_mean,opp_unikem_slow_mean,agg_unikem_total_mean,agg_unikem_fast_mean,agg_unikem_slow_mean,opp_rkem_total_mean,opp_rkem_fast_mean,opp_rkem_slow_mean,agg_rukem_total_mean,agg_rukem_fast_mean,agg_rukem_slow_mean,unikem_total_gain,unikem_fast_gain,unikem_slow_gain,rukem_total_gain,rukem_fast_gain,rukem_slow_gain,aggrukem_total_gain_over_aggunikem,aggrukem_fast_gain_over_aggunikem,aggrukem_slow_gain_over_aggunikem"
  for ratio in "${ratios[@]}"; do
    row=$(awk -F, -v data_dir="$DATA_DIR" -v ratio="$ratio" '
      function mean_for(protocol, party, path, value) {
        path = data_dir "/improvement_ratio_" ratio "_" protocol "_stats.csv"
        value = ""
        while ((getline line < path) > 0) {
          split(line, fields, ",")
          if (fields[1] == party) {
            value = fields[2] + 0
          }
        }
        close(path)
        if (value == "") {
          printf("missing %s party %s\n", path, party) > "/dev/stderr"
          exit 1
        }
        return value
      }
      function emit(value) {
        return sprintf("%.6f", value)
      }
      BEGIN {
        opp_unikem_a = mean_for("opp-uni-kem", "A")
        opp_unikem_b = mean_for("opp-uni-kem", "B")
        agg_unikem_a = mean_for("agg-uni-kem", "A")
        agg_unikem_b = mean_for("agg-uni-kem", "B")
        opp_rkem_a = mean_for("opp-rkem", "A")
        opp_rkem_b = mean_for("opp-rkem", "B")
        agg_rukem_a = mean_for("agg-rukem", "A")
        agg_rukem_b = mean_for("agg-rukem", "B")

        opp_unikem_total = (opp_unikem_a + opp_unikem_b) / 2.0
        agg_unikem_total = (agg_unikem_a + agg_unikem_b) / 2.0
        opp_rkem_total = (opp_rkem_a + opp_rkem_b) / 2.0
        agg_rukem_total = (agg_rukem_a + agg_rukem_b) / 2.0

        # Ratios >= 1 make Alice the fast party.  For ratio 1, Alice is used as
        # the conventional fast-party column and Bob as the slow-party column;
        # the protocols modeled here are symmetric up to sampling noise.
        opp_unikem_fast = opp_unikem_a
        agg_unikem_fast = agg_unikem_a
        opp_rkem_fast = opp_rkem_a
        agg_rukem_fast = agg_rukem_a
        opp_unikem_slow = opp_unikem_b
        agg_unikem_slow = agg_unikem_b
        opp_rkem_slow = opp_rkem_b
        agg_rukem_slow = agg_rukem_b

        printf("%s", ratio)
        printf(",%s,%s,%s", emit(opp_unikem_total), emit(opp_unikem_fast), emit(opp_unikem_slow))
        printf(",%s,%s,%s", emit(agg_unikem_total), emit(agg_unikem_fast), emit(agg_unikem_slow))
        printf(",%s,%s,%s", emit(opp_rkem_total), emit(opp_rkem_fast), emit(opp_rkem_slow))
        printf(",%s,%s,%s", emit(agg_rukem_total), emit(agg_rukem_fast), emit(agg_rukem_slow))
        printf(",%s,%s,%s", emit(opp_unikem_total / agg_unikem_total), emit(opp_unikem_fast / agg_unikem_fast), emit(opp_unikem_slow / agg_unikem_slow))
        printf(",%s,%s,%s", emit(opp_rkem_total / agg_rukem_total), emit(opp_rkem_fast / agg_rukem_fast), emit(opp_rkem_slow / agg_rukem_slow))
        printf(",%s,%s,%s\n", emit(agg_unikem_total / agg_rukem_total), emit(agg_unikem_fast / agg_rukem_fast), emit(agg_unikem_slow / agg_rukem_slow))
      }
    ')
    echo "$row"
  done
} > "$summary_csv"

gnuplot \
  -e "data_file='${summary_csv}'" \
  -e "plot_dir='${PLOT_DIR}'" \
  "$SCRIPT_DIR/aggressive_improvement_caps.gp"

gnuplot \
  -e "data_file='${summary_csv}'" \
  -e "plot_dir='${PLOT_DIR}'" \
  "$SCRIPT_DIR/aggrukem_vs_aggunikem_tradeoff.gp"

if [[ "$GENERATE_NUMBERS" == 1 ]]; then
  "$SCRIPT_DIR/generate_experiment_numbers.sh" \
    "$summary_csv" \
    "$EXPERIMENT_NUMBERS_OUT"
fi

if [[ "$GENERATE_TABLE" == 1 ]]; then
  "$SCRIPT_DIR/generate_experiment_table_tex.sh" \
    "$summary_csv" \
    "$EXPERIMENT_TABLE_OUT"
fi

echo "Wrote summary to $summary_csv"
echo "Wrote plots to $PLOT_DIR/aggressive_improvement_caps.png"
echo "Wrote plots to $PLOT_DIR/aggrukem_vs_aggunikem_tradeoff.png"
