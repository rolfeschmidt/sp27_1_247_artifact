if (!exists("data_dir")) data_dir = "data"
if (!exists("plot_dir")) plot_dir = "out"
if (!exists("ratio_slug")) ratio_slug = "1"
if (!exists("ratio_label")) ratio_label = "1"

set term pngcairo size 1400,900
set output sprintf("%s/ratio_%s_histogram.png", plot_dir, ratio_slug)

set datafile separator ","
set xlabel "|VulM| (Number of Exposed Messages)"
set ylabel "Frequency"
set xrange [0:*]
set yrange [0:*]
set key right top
set title sprintf("Vulnerable Message Set Size - Histogram Comparison\n(Ratio traffic, Alice:Bob = %s:1)", ratio_label)

plot sprintf("%s/ratio_%s_agg-uni-kem_hist.csv", data_dir, ratio_slug) using 1:2 with lines lw 3 title "Agg-UniKEM - A", \
     sprintf("%s/ratio_%s_agg-uni-kem_hist.csv", data_dir, ratio_slug) using 1:3 with lines lw 3 dt 2 title "Agg-UniKEM - B", \
     sprintf("%s/ratio_%s_agg-rukem_hist.csv", data_dir, ratio_slug) using 1:2 with lines lw 3 title "Agg-RUKEM - A", \
     sprintf("%s/ratio_%s_agg-rukem_hist.csv", data_dir, ratio_slug) using 1:3 with lines lw 3 dt 2 title "Agg-RUKEM - B", \
     sprintf("%s/ratio_%s_opp-uni-kem_hist.csv", data_dir, ratio_slug) using 1:2 with lines lw 3 title "Opp-UniKEM - A", \
     sprintf("%s/ratio_%s_opp-uni-kem_hist.csv", data_dir, ratio_slug) using 1:3 with lines lw 3 dt 2 title "Opp-UniKEM - B", \
     sprintf("%s/ratio_%s_opp-rkem_hist.csv", data_dir, ratio_slug) using 1:2 with lines lw 3 title "Opp-RKEM - A", \
     sprintf("%s/ratio_%s_opp-rkem_hist.csv", data_dir, ratio_slug) using 1:3 with lines lw 3 dt 2 title "Opp-RKEM - B"
