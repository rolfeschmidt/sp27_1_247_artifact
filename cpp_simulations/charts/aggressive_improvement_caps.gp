if (!exists("data_file")) data_file = "data/improvement_ratios.csv"
if (!exists("plot_dir")) plot_dir = "out"

set term pngcairo size 1200,760 enhanced font ",18"
set output sprintf("%s/aggressive_improvement_caps.png", plot_dir)

set datafile separator ","
set key left top spacing 1.15
set grid ytics lc rgb "#dddddd"
set xlabel "Alice:Bob send ratio"
set ylabel "Mean VMS ratio (opportunistic / aggressive)"
set xrange [1:10]
set xtics 1
set yrange [0.7:*]
set title "Aggressive Sending Improvement By Compromised Party"

set style line 1 lw 4 lc rgb "#0072B2" dt 1 pt 7 ps 1.1
set style line 2 lw 4 lc rgb "#0072B2" dt 2 pt 5 ps 1.1
set style line 3 lw 4 lc rgb "#D55E00" dt 1 pt 9 ps 1.1
set style line 4 lw 4 lc rgb "#D55E00" dt 2 pt 13 ps 1.1
set style line 5 lw 2 lc rgb "#333333" dt 3
set style line 6 lw 2 lc rgb "#777777" dt 4

plot data_file using 1:15 with linespoints ls 1 title "UniKEM family, fast party", \
     data_file using 1:16 with linespoints ls 2 title "UniKEM family, slow party", \
     data_file using 1:18 with linespoints ls 3 title "R(U)KEM family, fast party", \
     data_file using 1:19 with linespoints ls 4 title "R(U)KEM family, slow party", \
     1 with lines ls 5 title "parity", \
     3 with lines ls 6 title "3x reference"
