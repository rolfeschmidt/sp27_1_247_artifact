# Simulation Artifact Guide

This directory contains the C++ simulator used for the paper's vulnerable
message set experiments.

For reviewer-facing reproduction instructions, use the root-level artifact
README and scripts:

```sh
./reproduce_paper_numbers.sh
./reproduce_cdf_atlas.sh
```

Those scripts build this simulator, run the four paper protocols, and write
their regenerated outputs under `results/`.
