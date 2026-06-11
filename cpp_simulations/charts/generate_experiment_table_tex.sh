#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
DATA_FILE=${1:-"$SCRIPT_DIR/data/improvement_ratios.csv"}
OUT_FILE=${2:-"$SCRIPT_DIR/../../artifact/results/experiment_numbers_table.tex"}
TICKS=${TICKS:-100000}

format_ticks_tex() {
  case "$1" in
    1000) echo '$10^3$' ;;
    10000) echo '$10^4$' ;;
    100000) echo '$10^5$' ;;
    1000000) echo '$10^6$' ;;
    *) echo "$1" ;;
  esac
}

mkdir -p "$(dirname "$OUT_FILE")"

awk -F, -v ticks_tex="$(format_ticks_tex "$TICKS")" -v data_file="$DATA_FILE" '
  function mean(value) {
    return sprintf("%.1f", value + 0)
  }
  function ratio(value) {
    return sprintf("%.2f", value + 0)
  }
  function tex_escape_path(path) {
    gsub(/_/, "\\_", path)
    return path
  }
  function line(label, value, note) {
    printf("%s & %s & %s \\\\\n", label, value, note)
  }
  NR == 1 {
    for (i = 1; i <= NF; ++i) {
      col[$i] = i
    }
    next
  }
  $1 == 10 {
    found_10 = 1
    opp_unikem_fast = $(col["opp_unikem_fast_mean"])
    agg_unikem_fast = $(col["agg_unikem_fast_mean"])
    agg_unikem_slow = $(col["agg_unikem_slow_mean"])
    opp_rkem_fast = $(col["opp_rkem_fast_mean"])
    agg_rukem_fast = $(col["agg_rukem_fast_mean"])
    agg_rukem_slow = $(col["agg_rukem_slow_mean"])

    unikem_fast_gain = $(col["unikem_fast_gain"])
    unikem_slow_gain = $(col["unikem_slow_gain"])
    rukem_fast_gain = $(col["rukem_fast_gain"])
    rukem_slow_gain = $(col["rukem_slow_gain"])
    aggrukem_fast_gain_over_aggunikem = $(col["aggrukem_fast_gain_over_aggunikem"])
    aggrukem_slow_gain_over_aggunikem = $(col["aggrukem_slow_gain_over_aggunikem"])
  }
  $1 == 15 {
    found_15 = 1
    unikem_fast_gain_15 = $(col["unikem_fast_gain"])
  }
  $1 == 20 {
    found_20 = 1
    unikem_fast_gain_20 = $(col["unikem_fast_gain"])
  }
  {
    rows[++row_count] = sprintf("%s & %s & %s & %s & %s & %s \\\\",
      $1,
      ratio($(col["unikem_fast_gain"])),
      ratio($(col["rukem_fast_gain"])),
      ratio($(col["aggrukem_fast_gain_over_aggunikem"])),
      ratio($(col["aggrukem_slow_gain_over_aggunikem"])),
      mean($(col["agg_rukem_total_mean"])))
  }
  END {
    if (!found_10) {
      print "missing ratio 10 in " FILENAME > "/dev/stderr"
      exit 1
    }
    if (!found_15) {
      print "missing ratio 15 in " FILENAME > "/dev/stderr"
      exit 1
    }
    if (!found_20) {
      print "missing ratio 20 in " FILENAME > "/dev/stderr"
      exit 1
    }

    print "\\documentclass{article}"
    print "\\usepackage[margin=1in]{geometry}"
    print "\\usepackage{booktabs}"
    print "\\usepackage{longtable}"
    print "\\usepackage{array}"
    print "\\usepackage[T1]{fontenc}"
    print "\\begin{document}"
    print "\\section*{Experiment Values For Paper Comparison}"
    printf("Generated from \\texttt{%s}. Each simulation run uses %s ticks.\n\n",
      tex_escape_path(data_file), ticks_tex)

    print "\\subsection*{Values Used In The Paper Text}"
    print "\\small"
    print "\\begin{tabular}{@{}p{0.48\\linewidth}p{0.12\\linewidth}p{0.31\\linewidth}@{}}"
    print "\\toprule"
    print "Quantity & Value & Where to compare \\\\"
    print "\\midrule"
    line("Ticks per run", ticks_tex, "Experiment methodology")
    line("Agg-UniKEM fast-party gain at $10{:}1$", ratio(unikem_fast_gain) "$\\times$", "Benefits of aggressive sending")
    line("Agg-UniKEM fast-party gain at $15{:}1$", ratio(unikem_fast_gain_15) "$\\times$", "UniKEM improvement cap discussion")
    line("Agg-UniKEM fast-party gain at $20{:}1$", ratio(unikem_fast_gain_20) "$\\times$", "UniKEM improvement cap discussion")
    line("Agg-UniKEM slow-party gain at $10{:}1$", ratio(unikem_slow_gain) "$\\times$", "Slow-party parity claim")
    line("Agg-RUKEM fast-party gain over Opp-RKEM at $10{:}1$", ratio(rukem_fast_gain) "$\\times$", "R(U)KEM family comparison")
    line("Agg-RUKEM slow-party gain over Opp-RKEM at $10{:}1$", ratio(rukem_slow_gain) "$\\times$", "Slow-party parity claim")
    line("Agg-RUKEM fast-party gain over Agg-UniKEM at $10{:}1$", ratio(aggrukem_fast_gain_over_aggunikem) "$\\times$", "Aggressive protocol comparison")
    line("Agg-UniKEM slow-party mean divided by Agg-RUKEM at $10{:}1$", ratio(aggrukem_slow_gain_over_aggunikem) "$\\times$", "Aggressive protocol comparison")
    line("Opp-UniKEM fast-party mean at $10{:}1$", mean(opp_unikem_fast), "Main-text mean")
    line("Agg-UniKEM fast-party mean at $10{:}1$", mean(agg_unikem_fast), "Main-text mean")
    line("Agg-UniKEM slow-party mean at $10{:}1$", mean(agg_unikem_slow), "Main-text mean")
    line("Opp-RKEM fast-party mean at $10{:}1$", mean(opp_rkem_fast), "Main-text mean")
    line("Agg-RUKEM fast-party mean at $10{:}1$", mean(agg_rukem_fast), "Main-text mean")
    line("Agg-RUKEM slow-party mean at $10{:}1$", mean(agg_rukem_slow), "Main-text mean")
    print "\\bottomrule"
    print "\\end{tabular}"

    print "\\subsection*{Per-Ratio Summary}"
    print "\\begin{longtable}{@{}rrrrrr@{}}"
    print "\\toprule"
    print "Ratio & Uni fast & RU fast & RU/Uni fast & Uni/RU slow & RU total mean \\\\"
    print "\\midrule"
    for (i = 1; i <= row_count; ++i) {
      print rows[i]
    }
    print "\\bottomrule"
    print "\\end{longtable}"
    print "\\end{document}"
  }
' "$DATA_FILE" > "$OUT_FILE"

echo "Wrote experiment comparison table to $OUT_FILE"
