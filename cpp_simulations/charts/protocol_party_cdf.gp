if (!exists("data_dir")) data_dir = "data"
if (!exists("plot_dir")) plot_dir = "out"
if (!exists("ratio_slug")) ratio_slug = "1"
if (!exists("ratio_label")) ratio_label = "1"
if (!exists("protocol")) protocol = "agg-rukem"
if (!exists("protocol_title")) protocol_title = protocol
if (!exists("x_max")) x_max = 0

set term pngcairo size 1000,720 font ",20"
set output sprintf("%s/ratio_%s_%s_cdf.png", plot_dir, ratio_slug, protocol)

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
set title sprintf("%s, Alice:Bob = %s:1", protocol_title, ratio_label)
set grid ytics lc rgb "#dddddd"

set style line 1 lw 5 lc rgb "#1f77b4"
set style line 2 lw 5 lc rgb "#d62728" dt 2

plot sprintf("%s/ratio_%s_%s_hist.csv", data_dir, ratio_slug, protocol) using 1:4 with lines ls 1 title "Alice", \
     sprintf("%s/ratio_%s_%s_hist.csv", data_dir, ratio_slug, protocol) using 1:5 with lines ls 2 title "Bob"
