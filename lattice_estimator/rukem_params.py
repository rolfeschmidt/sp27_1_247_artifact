#! /usr/bin/env python3
"""
rukem_params.py
===============
Parameter analysis for the Ratcheting Updatable KEM (RUKEM) built on Katana
(referred to as UKatana).

Directory layout
----------------
Place this file and the martin_estimator/ folder in the same directory:

    your_directory/
    ├── rukem_params.py          ← this file
    └── martin_estimator/
        └── lattice_estimator/   ← Martin Albrecht's lattice-estimator
            ├── __init__.py
            └── ...

Note: Martin's estimator requires SageMath.

Dependencies
------------
  - SageMath  (required by Martin's lattice-estimator)
  - numpy     (for the DFP computation)

Usage
-----
    sage -python rukem_params.py

What this script computes
--------------------------
For each UKatana parameter set (targeting NIST Levels 1, 3, 5), and for each
update count k = 0, 1, 2, ... :

    k=0 is the non-updated key (Bob's initial "once-updated" key chi_1 = [2]*chi_0).
    k=1 is the 1st updated key ([3]*chi_0), and so on.
    In general, the k-th updated key has distribution chi_{k+1} = [k+2]*chi_0.

1.  Security hardness via Martin Albrecht's lattice-estimator.

    The RUKEM adversary always observes exactly one hint row in M*:
        M* = [ -s_hat^T | e_hat^T ]   with (s_hat, e_hat) ~ chi_{k+1} x chi_{k+1}.
    By Triple Ratchet Heuristic 3 (Eq. 8), the module rank ell cancels and:
        s_1(M*)^2  ~  n * sigma_hat^2
    where sigma_hat = std(chi_{k+1}).  Triple Ratchet Eq. (9) is the base case
    (k=0, chi_1 = [2]*chi_0) using sigma_hat ~ 2*sigma, giving
    s_1^2 ~ 4*n*sigma^2.  Scaling to chi_{k+1} = [k+2]*chi_0 gives:
        1/sigma_0^2 = 1/sigma^2 + 4*(k+1)*n*sigma^2/sigma_tilde^2
    where sigma     = std(chi_0) = sqrt(eta/2),
          sigma_tilde = std(SU(u,T)).
    As k grows, sigma_0 shrinks, tightening the hardness bound.

    The resulting MLWE instance (n_eff = ell*n, q, Gaussian(sigma_0)) is
    analysed via the primal uSVP attack with the ADPS16 Core-SVP cost model:
        coresvp_classic = floor(0.292 * beta)
        coresvp_quantum  = floor(0.265 * beta)
        bitsec           = CoreSVP + floor(log2((ell*n)^2 * beta))

2.  Exact decryption failure probability (DFP) for k = 0, 1, 2, ...
    until DFP exceeds DFP_STOP_LOG2, following the pq-crystals Kyber
    failure script approach (exact PMF convolution, no approximation).

    Noise term per output coefficient at update level k (Lemma B.3):

        z = s_k^T*e - e_k^T*s + e_tilde + delta

    where:
        s_k, e_k  ~  chi_{k+1} = [k+2]*chi_0  (Bob's key; k=0 -> chi_1 = [2]*chi_0)
        s, e      ~  chi_0 = CBD_eta       (Alice's fresh randomness)
        e_tilde   ~  SU(u, T)              (scalar ciphertext noise)
        delta     ~  compression noise from d-bit quantisation of v

    By symmetry and independence, z has the same distribution as a sum
    of 2*ell*n i.i.d. copies of [k+2]*chi_0 x chi_0,
    plus SU noise, plus delta.

    DFP = n * P[|z| > q/4]  (union bound over n=256 coefficients).
"""

# -- Standard library ---------------------------------------------------------
import math
import os
import sys
from math import ceil, factorial as fac, floor, log2, sqrt

# -- numpy (for DFP computation) ----------------------------------------------
import numpy as np

# -- Martin Albrecht's lattice-estimator --------------------------------------
# The martin_estimator/ folder must sit in the same directory as this script.
# Its inner package is named lattice_estimator/ -- no name clash with any
# other local package.
_HERE = os.path.dirname(os.path.abspath(__file__))
_MARTIN_PATH = os.path.join(_HERE, "martin_estimator")
if _MARTIN_PATH not in sys.path:
    sys.path.insert(0, _MARTIN_PATH)

try:
    from lattice_estimator import LWE, ND, RC
    _MARTIN_OK = True
except ImportError as _err:
    _MARTIN_OK = False
    import warnings
    warnings.warn(
        f"Martin's lattice-estimator could not be imported ({_err}).\n"
        f"Expected location: {_MARTIN_PATH}/lattice_estimator/\n"
        f"Hardness estimates will be skipped.",
        RuntimeWarning, stacklevel=1,
    )


# =============================================================================
# Configuration
# =============================================================================

# Stop the DFP table when log2(P_fail) first exceeds this value.
DFP_STOP_LOG2 = -100

# Set to False to omit the NIST Level 1 (UKatana-128) parameter set.
# Useful for producing paper tables that cover only Levels 3 and 5.
INCLUDE_KATANA_128 = False

# CoreSVP sieving constants
_CLASSIC_CONST = 0.292   # [ADPS16] classical Core-SVP gate count 2^{0.292*beta}
_QUANTUM_CONST  = 0.265   # [ADPS16] quantum  Core-SVP gate count 2^{0.265*beta}

# PMF tail-cutting threshold.  Entries below this are dropped so that
# float64 underflow does not accumulate in distribution tails.
_PMF_THRESHOLD = 2.0 ** (-300)


# =============================================================================
# PMF helper functions
# (exact array-based approach; mirrors proba_util.py from pq-crystals)
# =============================================================================

def _clean(arr, off):
    """Drop near-zero leading/trailing entries from a PMF (array, offset)."""
    mask = arr > _PMF_THRESHOLD
    if not mask.any():
        return np.array([1e-290]), 0
    lo = int(np.argmax(mask))
    hi = int(len(mask) - 1 - np.argmax(mask[::-1]))
    return arr[lo:hi + 1], off + lo


def _iconv(A, A_off, n):
    """n-fold self-convolution via binary doubling (= iter_law_convolution)."""
    r, r_off = np.array([1.0]), 0
    for ch in bin(n)[2:]:
        r = np.convolve(r, r)
        r, r_off = _clean(r, 2 * r_off)
        if ch == '1':
            r = np.convolve(r, A)
            r, r_off = _clean(r, r_off + A_off)
    return r, r_off


def _prod_dist(A, A_off, B, B_off):
    """PMF of X*Y for independent X~A, Y~B (= law_product)."""
    la, ha = A_off, A_off + len(A) - 1
    lb, hb = B_off, B_off + len(B) - 1
    extremes = [la * lb, la * hb, ha * lb, ha * hb, 0]
    lc, hc = min(extremes), max(extremes)
    C = np.zeros(hc - lc + 1)
    for i, pa in enumerate(A):
        if pa < _PMF_THRESHOLD:
            continue
        va = A_off + i
        for j, pb in enumerate(B):
            if pb < _PMF_THRESHOLD:
                continue
            C[va * (B_off + j) - lc] += pa * pb
    return C, lc


def _tail_prob(arr, off, t):
    """P[|X| > t]  (= tail_probability in proba_util.py)."""
    vals = np.arange(off, off + len(arr))
    return float(np.sum(arr[np.abs(vals) > t]))


def _build_cbd(eta):
    """PMF of CBD_eta as (array, offset)."""
    probs = np.array(
        [fac(2*eta) / fac(eta+k) / fac(eta-k) / 2.0**(2*eta)
         for k in range(-eta, eta + 1)],
        dtype=np.float64,
    )
    return probs, -eta


def _build_su(su_min, su_max, T):
    """PMF of SU(u,T) = T-fold sum of Uniform({su_min,...,su_max})."""
    size = su_max - su_min + 1
    return _iconv(np.full(size, 1.0 / size), su_min, T)


def _build_compression_noise(q, d_bits):
    """PMF of Decompress_q(Compress_q(x,d),d) - x, averaged over uniform x.

    Mirrors build_mod_switching_error_law in the Kyber pq-crystals script.
    """
    rq = 2 ** d_bits
    err_dist = {}
    for x in range(q):
        y = int(round(1.0 * rq * x / q) % rq)
        z = int(round(1.0 * q * y / rq))
        e = (x - z) % q
        if e >= q // 2:
            e -= q
        err_dist[e] = err_dist.get(e, 0) + 1.0 / q
    lo, hi = min(err_dist), max(err_dist)
    arr = np.zeros(hi - lo + 1)
    for v, p in err_dist.items():
        arr[v - lo] = p
    return arr, lo


# =============================================================================
# DFP computation
# =============================================================================

def compute_dfp(n, ell, q, eta, su_arr, su_off, da, da_off, k):
    """Exact decryption failure probability for UKatana RUKEM at update level k.

    Noise term  z = s_k^T*e - e_k^T*s + e_tilde + delta  (Lemma B.3).

    By symmetry of centred distributions and independence of the two inner
    products, z is distributed as:
        sum of 2*ell*n i.i.d. copies of [k+2]*chi_0 x chi_0
        +  SU(u,T) noise  +  delta

    where chi_{k+1} = [k+2]*chi_0 is Bob's key at update count k
    (k=0 gives chi_1 = [2]*chi_0, the non-updated key).

    Returns  n * P[|z| > q/4]  (union bound over n=256 coefficients).
    """
    cbd, cbd_off = _build_cbd(eta)

    # chi_{k+1} = [k+2]*chi_0: Bob's key at update count k (k=0 -> chi_1 = [2]*chi_0)
    upd, upd_off = _iconv(cbd, cbd_off, k + 2)

    # Single product term: [k+2]*chi_0 x chi_0
    B, B_off = _prod_dist(upd, upd_off, cbd, cbd_off)
    B, B_off = _clean(B, B_off)

    # Sum of 2*ell*n such terms
    C, C_off = _iconv(B, B_off, 2 * ell * n)

    # Add e_tilde ~ SU(u,T)
    w = np.convolve(C, su_arr)
    w, w_off = _clean(w, C_off + su_off)

    # Add delta (compression noise from d-bit quantisation of v)
    w = np.convolve(w, da)
    w, w_off = _clean(w, w_off + da_off)

    # Failure probability: union bound over n independent coefficients
    return n * _tail_prob(w, w_off, q / 4)


# =============================================================================
# Hardness computation
# =============================================================================

def compute_hardness(n, ell, q, eta, su_min, su_max, su_T, k):
    """Estimate MLWE hardness for UKatana RUKEM at update count k.

    Hint row: M* = [-s_hat^T | e_hat^T] with (s_hat, e_hat) ~ chi_{k+1} x chi_{k+1},
    where chi_{k+1} = [k+2]*chi_0  (k=0 -> chi_1 = [2]*chi_0, TR base case).

    Hardness formula (TR Heuristics 1-3, Eq. 7-9, generalised to update count k):
        1/sigma_0^2 = 1/sigma^2 + 4*(k+1)*n*sigma^2/sigma_tilde^2
    where sigma = std(chi_0) = sqrt(eta/2),  sigma_tilde = std(SU(u,T)).
    At k=0 this matches TR Eq. (9) exactly (factor 4*1 = 4).

    Returns a dict with keys:
        sigma_red, beta, coresvp_classic, coresvp_quantum,
        bitsec_classic, bitsec_quantum.
    Returns None if Martin's estimator is not available.
    """
    if not _MARTIN_OK:
        return None

    # Effective sigma_0 from the single-row hint matrix M* at level k
    var_sk    = eta / 2                                        # var(chi_0)
    var_noise = su_T * ((su_max - su_min + 1) ** 2 - 1) / 12  # var(SU)
    var_red   = 1 / ((1 / var_sk) + (4 * (k + 1) * n * var_sk / var_noise))
    sigma_red = sqrt(var_red)

    # Module descent to integer LWE dimension ell*n
    n_eff = ell * n

    # Primal uSVP attack via Martin's estimator (ADPS16 Core-SVP model)
    params = LWE.Parameters(
        n  = n_eff,
        q  = q,
        Xs = ND.DiscreteGaussian(sigma_red),
        Xe = ND.DiscreteGaussian(sigma_red),
    )
    res  = LWE.primal_usvp(params, red_cost_model=RC.ADPS16)
    beta = int(res["beta"])

    # CoreSVP and bit-security
    coresvp_classic = floor(_CLASSIC_CONST * beta)
    coresvp_quantum  = floor(_QUANTUM_CONST  * beta)
    log_term        = floor(log2((ell * n) ** 2 * beta))
    bitsec_classic  = coresvp_classic + log_term
    bitsec_quantum   = coresvp_quantum  + log_term

    return dict(
        sigma_red       = sigma_red,
        beta            = beta,
        coresvp_classic = coresvp_classic,
        coresvp_quantum  = coresvp_quantum,
        bitsec_classic  = bitsec_classic,
        bitsec_quantum   = bitsec_quantum,
    )


# =============================================================================
# UKatana parameter sets
# =============================================================================

# Each tuple: (name, NIST_level, lam, n, ell, q, eta, su_u, su_T, dv)
# ell  = module rank (dimension of public matrix A in R_q^{ell x ell})
# lam  = security parameter lambda (bit-length of seed)
# |ct| = lam * dv / 8
KATANA_PARAMS = [
#    ("Katana-128", 1, 128, 256, 2,  7681, 4, 7, 4, 3),
    ("UKatana-192", 3, 192, 256, 3,  7681, 2,  8, 1, 3),
    ("UKatana-256", 5, 256, 256, 4, 12289, 2, 10, 1, 3),
]


# =============================================================================
# Output
# =============================================================================

def analyse_one(name, nist, lam, n, ell, q, eta, su_u, su_T, dv,
                dfp_stop=DFP_STOP_LOG2):
    ek_bytes = n * ell * ceil(log2(q)) // 8
    ct_bytes = lam * dv // 8  # lam = lambda (128 / 192 / 256)
    su_min   = -(1 << (su_u - 1))
    su_max   =  (1 << (su_u - 1)) - 1

    sep = "=" * 68
    print(f"\n{sep}")
    print(f"  {name}  (NIST Level {nist})")
    print(sep)
    print(f"  n={n}, ell={ell}, q={q}, eta={eta}, SU({su_u},{su_T}), dv={dv}")
    print(f"  |ek|={ek_bytes}B,  |ct|={ct_bytes}B,  "
          f"|ek|+|ct|={ek_bytes + ct_bytes}B")
    print(f"\n  [DFP + Hardness per k]")
    print(f"  Hardness: hint-MLWE reduction (1 hint row, chi_{{k+1}} noise), RC.ADPS16")
    print(f"  DFP: noise = e_tilde + delta  |  "
          f"stopping at log2(P) > {dfp_stop}")

    su_arr, su_off = _build_su(su_min, su_max, su_T)
    da, da_off     = _build_compression_noise(q, dv)

    print()
    hdr = (f"  {'k':>3}   {'log2(P_fail)':>14}   "
           f"{'CoreSVP':>8}   {'bitsec':>7}   {'<= 2^{' + str(dfp_stop) + '}?':>12}")
    print(hdr)
    print(f"  {'-' * 58}")

    dfp_results      = {}  # k -> log2(P_fail)
    hardness_results = {}  # k -> hardness dict (or None)

    for k in range(0, 60):
        pf = compute_dfp(n, ell, q, eta, su_arr, su_off, da, da_off, k)
        lp = math.log2(pf) if pf > 0 else float('-inf')
        dfp_results[k] = lp

        h = compute_hardness(n, ell, q, eta, su_min, su_max, su_T, k)
        hardness_results[k] = h

        lp_str  = ("    < 2^{-300}" if lp == float('-inf')
                   else f"  2^{{{lp:7.2f}}}")
        csv_str = f"{h['coresvp_classic']:>8}" if h else f"{'---':>8}"
        bts_str = f"{h['bitsec_classic']:>7}" if h else f"{'---':>7}"
        ok      = "OK" if lp <= dfp_stop else "FAIL"
        tag     = "  <- non-updated UKatana (k=0, chi_1 = [2]*chi_0)" if k == 0 else ""
        print(f"  {k:>3}   {lp_str:>14}   {csv_str}   {bts_str}   {ok:>12}{tag}")

        if lp > dfp_stop:
            break

    max_ok = max((k for k, lp in dfp_results.items() if lp <= dfp_stop),
                 default=-1)
    print(f"\n  Max k with DFP <= 2^{{{dfp_stop}}}: k = {max_ok}")

    return dfp_results, hardness_results


def main():
    print("=" * 68)
    print("  UKatana RUKEM Parameter Analysis")
    print(f"  Noise: z = s_k^T*e - e_k^T*s + e_tilde + delta  (Lemma B.3)")
    print(f"  DFP stopping threshold: 2^{{{DFP_STOP_LOG2}}}")
    status = "OK" if _MARTIN_OK else "NOT FOUND -- hardness will be skipped"
    print(f"  Martin's lattice-estimator: {status}")
    print("=" * 68)

    active_params = [p for p in KATANA_PARAMS if INCLUDE_KATANA_128 or p[1] != 1]

    all_dfp      = {}
    all_hardness = {}
    for params in active_params:
        name = params[0]
        dfp_res, h_res = analyse_one(*params)
        all_dfp[name]      = dfp_res
        all_hardness[name] = h_res

    # -- Summary table ---------------------------------------------------------
    # CoreSVP shown at k=0 (non-updated) and at Max k (binding security level).
    print(f"\n\n{'=' * 80}")
    print("  SUMMARY  (security levels shown at k=0 and at Max k)")
    print(f"{'=' * 80}")
    print(f"  {'Scheme':<14}  "
          f"{'CoreSVP(k=0)':>13}  {'bitsec(k=0)':>12}  "
          f"{'CoreSVP(MaxK)':>14}  {'bitsec(MaxK)':>13}  "
          f"{'SU':>6}  {'dv':>3}  {'|ek|':>6}  {'|ct|':>5}  "
          f"{'|ek|+|ct|':>10}  {'Max k':>6}")
    print(f"  {'-' * 103}")

    for params in active_params:
        name, nist, lam, n, ell, q, eta, su_u, su_T, dv = params
        ek = n * ell * ceil(log2(q)) // 8
        ct = lam * dv // 8
        dfp_res = all_dfp[name]
        h_res   = all_hardness[name]

        max_ok  = max((k for k, lp in dfp_res.items() if lp <= DFP_STOP_LOG2),
                      default=-1)
        h_k0    = h_res.get(0)
        h_maxk  = h_res.get(max_ok)
        def _csv(h): return f"{h['coresvp_classic']:>13}" if h else f"{'---':>13}"
        def _bts(h): return f"{h['bitsec_classic']:>12}" if h else f"{'---':>12}"
        su_str  = f"({su_u},{su_T})"

        print(f"  {name:<14}  "
              f"{_csv(h_k0)}  {_bts(h_k0)}  "
              f"{_csv(h_maxk):>14}  {_bts(h_maxk):>13}  "
              f"{su_str:>6}  {dv:>3}  {ek:>5}B  {ct:>4}B  "
              f"{ek + ct:>9}B  {max_ok:>6}")

    print(f"{'=' * 80}")
    print()
    print("  CoreSVP_classic = floor(0.292 * beta)  [ADPS16 Core-SVP model]")
    print("  CoreSVP_quantum  = floor(0.265 * beta)  [ADPS16]")
    print("  bitsec           = CoreSVP + floor(log2((ell*n)^2 * beta))")
    print("  Hardness formula : 1/sigma_0^2 = 1/sigma^2 + 4*(k+1)*n*sigma^2/sigma_tilde^2")
    print("  (1 hint row with chi_{k+1} = [k+2]*chi_0; k = update count, k=0 -> chi_1 = [2]*chi_0)")


if __name__ == "__main__":
    main()
