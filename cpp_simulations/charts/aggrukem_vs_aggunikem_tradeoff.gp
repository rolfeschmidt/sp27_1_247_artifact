if (!exists("data_file")) data_file = "data/improvement_ratios.csv"
if (!exists("plot_dir")) plot_dir = "out"

set term pngcairo size 1200,760 enhanced font ",18"
set output sprintf("%s/aggrukem_vs_aggunikem_tradeoff.png", plot_dir)

set datafile separator ","
set key left top spacing 1.15
set grid ytics lc rgb "#dddddd"
set xlabel "Alice:Bob send ratio"
set ylabel "Agg-UniKEM mean VMS / Agg-RUKEM mean VMS"
set xrange [1:10]
set xtics 1
set yrange [0.7:*]
set title "Agg-RUKEM Relative To Agg-UniKEM"

set style line 1 lw 4 lc rgb "#0072B2" dt 1 pt 7 ps 1.1
set style line 2 lw 4 lc rgb "#D55E00" dt 2 pt 13 ps 1.1
set style line 3 lw 4 lc rgb "#009E73" dt 4 pt 5 ps 1.1
set style line 4 lw 2 lc rgb "#333333" dt 3

plot data_file using 1:20 with linespoints ls 3 title "total", \
     data_file using 1:21 with linespoints ls 1 title "fast party", \
     data_file using 1:22 with linespoints ls 2 title "slow party", \
     1 with lines ls 4 title "parity"
