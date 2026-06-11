# UKatana Parameter Analysis

## Contents

```
lattice_estimator/
├── rukem_params.py          ← main analysis script
└── martin_estimator/
    └── lattice_estimator/   ← Martin Albrecht's lattice-estimator (vendored)
```

**`rukem_params.py`** computes, for each UKatana parameter set (targeting NIST
Levels 1, 3, 5), and for each update count k = 0, 1, 2, ...:

- k=0 is the non-updated baseline: Bob's key is χ₁ = [2]·χ₀ = [2]·CBD(η).
- k=1 is the first updated key: [3]·χ₀. In general, the k-th updated key
  has distribution χ_{k+1} = [k+2]·χ₀.

For each k the script computes:

1. **Exact decryption failure probability (DFP)** via exact PMF convolution
   (no Gaussian approximation), following the pq-crystals Kyber failure
   probability script. The noise term per output coefficient (Lemma B.3) is:

       z = s_k^T * e  -  e_k^T * s  +  e_tilde  +  delta

   where `(s_k, e_k) ~ chi_{k+1} x chi_{k+1}` with `chi_{k+1} = [k+2]*chi_0`
   (Bob's key at update count k), `(s, e) ~ chi_0 x chi_0` (Alice's fresh
   randomness), `e_tilde ~ SU(u,T)` (scalar ciphertext noise), and `delta` is
   the compression noise from d-bit quantisation of v.

2. **Hardness estimates** — CoreSVP and bit-security via the primal uSVP
   attack, using Martin Albrecht's lattice-estimator with the ADPS16 Core-SVP
   cost model. Both classical and quantum estimates are reported. Hardness is
   recomputed at every k (see Methodology below).

The script iterates k = 0, 1, 2, ... until the DFP first exceeds the threshold
`2^{-100}` (configurable via `DFP_STOP_LOG2`). It then prints a per-k table and
a summary table across all active parameter sets.

**`martin_estimator/`** contains Martin Albrecht's public lattice-estimator
(https://github.com/malb/lattice-estimator), vendored here so that the
artifact is self-contained. It requires SageMath to run.

---

## Recovering base Katana (k=0) parameters

The k=0 row corresponds to the non-updated UKatana key. At k=0, Bob's key is
χ₁ = [2]·χ₀ (the once-updated distribution) and the hardness formula gives
`1/σ₀² = 1/σ² + 4·n·σ²/σ̃²`, which matches Triple Ratchet Eq. (9) exactly.
The k=0 DFP and CoreSVP therefore serve as the baseline for comparison with
the updated parameters at k > 0.

---

## Flags

`INCLUDE_KATANA_128` — set to `True` to include the NIST Level 1 parameter set;
`False` to omit it (current default). Useful for producing paper tables covering
only Levels 3 and 5.

---

## Prerequisites

| Dependency        | Purpose                                   | How to obtain            |
|-------------------|-------------------------------------------|--------------------------|
| **SageMath >= 9** | Required by Martin's lattice-estimator    | https://www.sagemath.org |
| **numpy**         | PMF convolution in `rukem_params.py`      | `pip install numpy`      |

All other imports (`math`, `os`, `sys`) are Python standard library.

A Nix flake is included (`flake.nix`, `flake.lock`) providing a reproducible
environment with SageMath and NumPy.

---

## Running the script

```bash
sage -python rukem_params.py
```

Using the bundled Nix environment:

```bash
nix develop --extra-experimental-features 'nix-command flakes' -c run-rukem
```

If SageMath is unavailable, a warning is printed and hardness estimates are
skipped; the DFP table still runs in full.

---

## Methodology

### Hardness

The RUKEM adversary always observes exactly one hint row
`M* = [-s_hat^T | e_hat^T]` with `(s_hat, e_hat) ~ chi_{k+1} x chi_{k+1}`,
where `chi_{k+1} = [k+2]*chi_0` is Bob's key at update count k.

By Triple Ratchet Heuristic 3 (Eq. 8), the module rank ell cancels and
`s_1(M*)^2 ~ n * sigma_hat^2` where `sigma_hat = std(chi_{k+1})`. The base
case k=0 (`chi_1 = [2]*chi_0`) uses `sigma_hat ~ 2*sigma` (a heuristic
overestimate), giving `s_1^2 ~ 4*n*sigma^2` and Triple Ratchet Eq. (9).
Scaling to `chi_{k+1} = [k+2]*chi_0` and substituting into the hint-MLWE to
MLWE reduction gives:

    1/sigma_0^2 = 1/sigma^2 + 4*(k+1)*n*sigma^2/sigma_tilde^2

where `sigma = std(chi_0) = sqrt(eta/2)` and `sigma_tilde = std(SU(u,T))`.
As k grows, sigma_0 shrinks, tightening the hardness bound.

The resulting MLWE instance (dimension `ell*n`, modulus `q`, Gaussian noise
`sigma_0`) is analysed via `LWE.primal_usvp` with `RC.ADPS16`. CoreSVP and
bit-security are defined as:

    CoreSVP_classic = floor(0.292 * beta)
    CoreSVP_quantum  = floor(0.265 * beta)
    bitsec           = CoreSVP + floor(log2((ell*n)^2 * beta))

### DFP

All distributions are represented as exact probability mass functions (PMFs)
and combined via exact convolution (binary-doubling for self-convolutions,
direct product for independent multiplications). No Gaussian approximation
or variance-based bound is used. The failure probability is reported as the
union bound over n = 256 independent coefficients:

    DFP = n * P[|z| > q/4]

---

## Parameter sets

| Scheme       | NIST Level | n   | ell | q     | eta | su_u | su_T | dv | \|ct\| |
|--------------|------------|-----|-----|-------|-----|------|------|----|--------|
| UKatana-192  | 3          | 256 | 3   | 10753 | 4   | 8    | 1    | 6  | 144 B  |
| UKatana-256  | 5          | 256 | 4   | 15361 | 4   | 9    | 1    | 5  | 160 B  |

Ciphertext size: `|ct| = lambda * dv / 8` bytes, where `lambda` is the
security parameter (192 / 256 per scheme).

Encapsulation key size: `|ek| = n * ell * ceil(log2(q)) / 8` bytes
(1344 B / 1792 B for Levels 3 / 5).
