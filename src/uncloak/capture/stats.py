"""
Mathematical Engine for Robust Timing Dispersion & Payload Statistics.
Computes Median, MAD, IQR, and Bowley Skewness according to Feature Schema v1.
"""

from __future__ import annotations

import math
from typing import Any


def _median(values: list[float]) -> float:
    """Calculates median of a list of floats."""
    if not values:
        return 0.0
    sorted_v = sorted(values)
    n = len(sorted_v)
    mid = n // 2
    if n % 2 == 1:
        return sorted_v[mid]
    return (sorted_v[mid - 1] + sorted_v[mid]) / 2.0


def _quartiles(values: list[float]) -> tuple[float, float, float]:
    """Computes Q1, Q2 (median), and Q3 using method 2 (Tukey)."""
    if not values:
        return 0.0, 0.0, 0.0
    sorted_v = sorted(values)
    n = len(sorted_v)
    q2 = _median(sorted_v)
    mid = n // 2
    if n % 2 == 0:
        q1 = _median(sorted_v[:mid])
        q3 = _median(sorted_v[mid:])
    else:
        q1 = _median(sorted_v[:mid])
        q3 = _median(sorted_v[mid + 1:])
    return q1, q2, q3


def compute_burst_stats(
    inter_arrival_times: list[float],
    sizes_out: list[float],
    sizes_in: list[float],
) -> dict[str, float]:
    """
    Computes robust timing dispersion and size statistics for Feature Schema v1:
      - iat_median: Median inter-arrival time in seconds.
      - iat_mad_ratio: MAD(IAT) / median(IAT) (normalized dispersion).
      - iat_iqr_ratio: IQR(IAT) / median(IAT).
      - iat_bowley_skew: (Q3 + Q1 - 2*Q2) / (Q3 - Q1) (-1.0 to 1.0, 0 for symmetric uniform jitter).
      - size_out_median: Median bytes transmitted.
      - size_in_median: Median bytes received.
      - size_mad_ratio: MAD(size_out) / median(size_out).
    """
    if not inter_arrival_times:
        return {
            "iat_median": 0.0,
            "iat_mad_ratio": 0.0,
            "iat_iqr_ratio": 0.0,
            "iat_bowley_skew": 0.0,
            "size_out_median": _median(sizes_out),
            "size_in_median": _median(sizes_in),
            "size_mad_ratio": 0.0,
        }

    # Inter-Arrival Timing Statistics
    iat_med = _median(inter_arrival_times)
    iat_deviations = [abs(x - iat_med) for x in inter_arrival_times]
    iat_mad = _median(iat_deviations)

    q1, q2, q3 = _quartiles(inter_arrival_times)
    iqr = q3 - q1

    # Ratio normalizations avoiding division by zero
    iat_mad_ratio = (iat_mad / iat_med) if iat_med > 1e-6 else 0.0
    iat_iqr_ratio = (iqr / iat_med) if iat_med > 1e-6 else 0.0

    # Bowley Skewness Coefficient
    if iqr > 1e-6:
        iat_bowley_skew = (q3 + q1 - 2.0 * q2) / iqr
    else:
        iat_bowley_skew = 0.0

    # Payload Size Statistics
    size_out_med = _median(sizes_out)
    size_in_med = _median(sizes_in)

    size_out_devs = [abs(x - size_out_med) for x in sizes_out]
    size_out_mad = _median(size_out_devs)
    size_mad_ratio = (size_out_mad / size_out_med) if size_out_med > 1e-6 else 0.0

    return {
        "iat_median": round(iat_med, 4),
        "iat_mad_ratio": round(iat_mad_ratio, 4),
        "iat_iqr_ratio": round(iat_iqr_ratio, 4),
        "iat_bowley_skew": round(iat_bowley_skew, 4),
        "size_out_median": round(size_out_med, 2),
        "size_in_median": round(size_in_med, 2),
        "size_mad_ratio": round(size_mad_ratio, 4),
    }
