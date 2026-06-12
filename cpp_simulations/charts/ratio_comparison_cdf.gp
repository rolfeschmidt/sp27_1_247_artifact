if (!exists("data_dir")) data_dir = "data"
if (!exists("plot_dir")) plot_dir = "out"
if (!exists("ratio_slug")) ratio_slug = "1"
if (!exists("ratio_label")) ratio_label = "1"
if (!exists("x_max")) x_max = 0

set term pngcairo size 1400,900 enhanced font "DejaVu Sans,24"
set output sprintf("%s/ratio_%s_cdf.png", plot_dir, ratio_slug)

set datafile separator ","
set xlabel "|VulM| (Number of Exposed Messages)" font ",30" offset 0,-0.6
set ylabel "Cumulative Probability" font ",30" offset -1.0,0
set tics font ",24"
if (x_max > 0) {
  set xrange [0:x_max]
} else {
  set xrange [0:*]
}
set yrange [0:1]
set key right bottom font ",22" spacing 1.08 samplen 2.8
set title sprintf("Vulnerable Message Set Size - CDF Comparison\n(Ratio traffic, Alice:Bob = %s:1)", ratio_label) font ",30"
set lmargin 12
set rmargin 3
set tmargin 4
set bmargin 5

set style line 1 lw 5 lc rgb "#1f77b4" dt 1
set style line 2 lw 5 lc rgb "#1f77b4" dt 2 pt 5 ps 1.55 pi 45
set style line 3 lw 5 lc rgb "#2ca02c" dt 1
set style line 4 lw 5 lc rgb "#2ca02c" dt 2 pt 9 ps 1.55 pi 45
set style line 5 lw 5 lc rgb "#d62728" dt 1
set style line 6 lw 5 lc rgb "#d62728" dt 2 pt 7 ps 1.55 pi 45
set style line 7 lw 5 lc rgb "#ff9900" dt 1
set style line 8 lw 5 lc rgb "#ff9900" dt 2 pt 13 ps 1.55 pi 45

plot sprintf("%s/ratio_%s_opp-uni-kem_hist.csv", data_dir, ratio_slug) using 1:4 with lines ls 1 title "Opp-UniKEM - A", \
     sprintf("%s/ratio_%s_opp-uni-kem_hist.csv", data_dir, ratio_slug) using 1:5 with linespoints ls 2 title "Opp-UniKEM - B", \
     sprintf("%s/ratio_%s_agg-uni-kem_hist.csv", data_dir, ratio_slug) using 1:4 with lines ls 3 title "Agg-UniKEM - A", \
     sprintf("%s/ratio_%s_agg-uni-kem_hist.csv", data_dir, ratio_slug) using 1:5 with linespoints ls 4 title "Agg-UniKEM - B", \
     sprintf("%s/ratio_%s_opp-rkem_hist.csv", data_dir, ratio_slug) using 1:4 with lines ls 5 title "Opp-RKEM - A", \
     sprintf("%s/ratio_%s_opp-rkem_hist.csv", data_dir, ratio_slug) using 1:5 with linespoints ls 6 title "Opp-RKEM - B", \
     sprintf("%s/ratio_%s_agg-rukem_hist.csv", data_dir, ratio_slug) using 1:4 with lines ls 7 title "Agg-RUKEM - A", \
     sprintf("%s/ratio_%s_agg-rukem_hist.csv", data_dir, ratio_slug) using 1:5 with linespoints ls 8 title "Agg-RUKEM - B"
