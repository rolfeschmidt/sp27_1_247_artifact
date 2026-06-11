if (!exists("data_dir")) data_dir = "data"
if (!exists("plot_dir")) plot_dir = "out"
if (!exists("ratio_slug")) ratio_slug = "1"
if (!exists("ratio_label")) ratio_label = "1:1"
if (!exists("party_col")) party_col = 4
if (!exists("plot_title")) plot_title = sprintf("%s sending", ratio_label)
if (!exists("x_max")) x_max = 0

set term pngcairo size 1000,720 font ",22"
set output sprintf("%s/ratio_%s_fast_sender_cdf.png", plot_dir, ratio_slug)

set datafile separator ","
set xlabel "|VulM|"
set ylabel "CDF"
if (x_max > 0) {
  set xrange [0:x_max]
} else {
  set xrange [0:*]
}
set yrange [0:1]
set key right bottom spacing 1.15
set title plot_title
set grid ytics lc rgb "#dddddd"

set style line 1 lw 5 lc rgb "#1f77b4"
set style line 2 lw 5 lc rgb "#d62728"
set style line 3 lw 5 lc rgb "#2ca02c" dt 2
set style line 4 lw 5 lc rgb "#ff9900" dt 3

plot sprintf("%s/ratio_%s_opp-uni-kem_hist.csv", data_dir, ratio_slug) using 1:party_col with lines ls 1 title "Opp-UniKEM", \
     sprintf("%s/ratio_%s_opp-rkem_hist.csv", data_dir, ratio_slug) using 1:party_col with lines ls 2 title "Opp-RKEM", \
     sprintf("%s/ratio_%s_agg-uni-kem_hist.csv", data_dir, ratio_slug) using 1:party_col with lines ls 3 title "Agg-UniKEM", \
     sprintf("%s/ratio_%s_agg-rukem_hist.csv", data_dir, ratio_slug) using 1:party_col with lines ls 4 title "Agg-RUKEM"
