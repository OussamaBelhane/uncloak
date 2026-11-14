"""
C2 Classification & Explainability Engine for Uncloak (Feature Schema v1).
Evaluates frozen 12-feature FlowFeaturesV1 vectors using loaded JSON/ML weights or calibrated v1 heuristics.
"""

from __future__ import annotations

import json
import logging
import math
from dataclasses import asdict
from pathlib import Path
from typing import Any, Optional, Union

import numpy as np

from uncloak.core.models import FlowFeaturesV1

logger = logging.getLogger("uncloak.detection")

FEATURE_NAMES_V1 = [
    "n_bursts",
    "iat_median",
    "iat_mad_ratio",
    "iat_iqr_ratio",
    "iat_bowley_skew",
    "size_out_median",
    "size_in_median",
    "size_mad_ratio",
    "conn_per_burst",
    "raw_ip_flag",
    "proc_signed",
    "proc_path_class",
]

# Legacy alias preserved for backward compatibility
FEATURE_NAMES = FEATURE_NAMES_V1


def _to_feature_dict(features: Union[FlowFeaturesV1, dict[str, Any]]) -> dict[str, float]:
    """Normalizes a FlowFeaturesV1 dataclass or dictionary into float-valued Feature Schema v1 fields."""
    if isinstance(features, FlowFeaturesV1):
        raw = asdict(features)
        return {k: float(raw.get(k, 0.0) or 0.0) for k in FEATURE_NAMES_V1}

    # Support both Feature Schema v1 dicts and legacy dict keys gracefully
    if "iat_mad_ratio" in features:
        return {k: float(features.get(k, 0.0) or 0.0) for k in FEATURE_NAMES_V1}

    legacy_cv = float(features.get("delta_t_cv", 1.0))
    return {
        "n_bursts": float(features.get("n_bursts", 12)),
        "iat_median": float(features.get("delta_t_mean", 0.0)),
        "iat_mad_ratio": legacy_cv * 0.75,
        "iat_iqr_ratio": legacy_cv * 1.15,
        "iat_bowley_skew": 0.0,
        "size_out_median": float(features.get("burst_bytes_iqr", 512.0)),
        "size_in_median": 256.0,
        "size_mad_ratio": 0.05 if float(features.get("payload_packet_ratio", 0.0)) > 0.7 else 0.45,
        "conn_per_burst": 1.0,
        "raw_ip_flag": float(features.get("sni_asn_mismatch", 0.0)),
        "proc_signed": 1.0,
        "proc_path_class": 0.0,
    }


class C2Predictor:
    """Evaluates FlowFeaturesV1 vectors and generates calibrated threat scores & SOC explanations."""

    def __init__(self, model_path: Optional[Union[Path, str]] = None) -> None:
        if model_path is None:
            self.model_path = Path(__file__).resolve().parent / "c2_model_v1.json"
        else:
            self.model_path = Path(model_path)

        self.model: Optional[Any] = None
        self.weights: Optional[dict[str, Any]] = None
        self._load_model()

    def _load_model(self) -> None:
        """Loads safe JSON model weights if present (zero unsafe pickle deserialization)."""
        if self.model_path.exists() and self.model_path.suffix.lower() == ".json":
            try:
                with open(self.model_path, "r", encoding="utf-8") as f:
                    self.weights = json.load(f)
                logger.info("Loaded C2 JSON model weights from %s", self.model_path)
                return
            except Exception as exc:
                logger.warning("Failed reading JSON weights at %s: %s", self.model_path, exc)

        logger.info("Operating with calibrated Feature Schema v1 statistical beacon engine.")

    def predict_v1(
        self,
        features: Union[FlowFeaturesV1, dict[str, Any]],
        host_context_known: bool = True,
    ) -> dict[str, Any]:
        """
        Scores a single FlowFeaturesV1 record (or normalized dictionary) and outputs
        a calibrated threat probability, verdict tier, MITRE hint, and explainable top reasons.
        """
        f = _to_feature_dict(features)
        vector = np.array([[f[name] for name in FEATURE_NAMES_V1]], dtype=np.float32)

        if self.weights is not None:
            proba = self._score_from_json_weights(vector[0])
        else:
            proba = self._calibrated_v1_score(f, host_context_known=host_context_known)

        if proba >= 0.88:
            level = "CRITICAL"
            is_c2 = True
        elif proba >= 0.75:
            level = "HIGH"
            is_c2 = True
        elif proba >= 0.48:
            level = "EVALUATING"
            is_c2 = False
        else:
            level = "HEALTHY"
            is_c2 = False

        reasons, profile_hint, mitre_technique = self._explain_v1(f, proba, host_context_known)

        return {
            "threat_score": round(proba, 4),
            "is_c2": is_c2,
            "confidence_level": level,
            "c2_profile_hint": profile_hint,
            "mitre_technique": mitre_technique,
            "top_features": reasons,
            "feature_vector_v1": f,
        }

    def predict_flow(self, features: Union[FlowFeaturesV1, dict[str, Any]]) -> dict[str, Any]:
        """Unified prediction entrypoint supporting both FlowFeaturesV1 and feature dicts."""
        return self.predict_v1(features)

    def _score_from_json_weights(self, vec: np.ndarray) -> float:
        """Evaluates a linear/calibrated JSON weight vector safely without pickle."""
        if not self.weights:
            return 0.5
        coef = np.array(self.weights.get("coef", [0.0] * len(FEATURE_NAMES_V1)), dtype=np.float32)
        intercept = float(self.weights.get("intercept", 0.0))
        z = float(np.dot(vec, coef) + intercept)
        proba = 1.0 / (1.0 + math.exp(-max(-20.0, min(20.0, z))))
        return min(0.995, max(0.001, proba))

    def _calibrated_v1_score(self, f: dict[str, float], host_context_known: bool = True) -> float:
        """
        Calibrated statistical + behavioral beacon scoring model aligned with Module 12
        Feature Schema v1:
          - Timing periodicity: iat_mad_ratio, iat_iqr_ratio, iat_bowley_skew, iat_median
          - Payload invariance: size_mad_ratio, size_out_median
          - Connection geometry: conn_per_burst, raw_ip_flag
          - Endpoint attribution: proc_signed, proc_path_class
        """
        n_bursts = f["n_bursts"]
        iat_med = f["iat_median"]
        mad = f["iat_mad_ratio"]
        iqr = f["iat_iqr_ratio"]
        skew = abs(f["iat_bowley_skew"])
        size_mad = f["size_mad_ratio"]
        conn_burst = f["conn_per_burst"]
        raw_ip = int(f["raw_ip_flag"])
        proc_signed = int(f["proc_signed"])
        path_class = int(f["proc_path_class"])

        if n_bursts < 4 or iat_med < 0.4:
            return 0.012

        # 1. Core timing periodicity score (works for both live sensor and offline PCAP)
        score = 0.02
        if mad <= 0.10:
            score += 0.48
        elif mad <= 0.18:
            score += 0.36
        elif mad <= 0.28:
            score += 0.20
        elif mad >= 0.45:
            # High dispersion indicates organic human web browsing
            score -= 0.15

        if iqr <= 0.18:
            score += 0.16
        elif iqr <= 0.30:
            score += 0.09

        # Uniform / symmetric sleep jitter signature (e.g. Sliver/Cobalt jitter window)
        if mad <= 0.25 and skew <= 0.22:
            score += 0.08

        # 2. Fixed heartbeat size signature (low payload MAD ratio)
        if size_mad <= 0.08 and mad <= 0.28:
            score += 0.12
        elif size_mad <= 0.20 and mad <= 0.28:
            score += 0.06

        # 3. Direct raw IP egress without prior DNS resolution
        if raw_ip == 1:
            score += 0.16

        # 4. Persistent vs polling connection ratio boost for rhythmic beacons
        if mad <= 0.25 and iat_med >= 2.0:
            if conn_burst <= 0.15:
                score += 0.05  # Persistent mTLS / long-lived C2 channel
            elif conn_burst >= 0.85:
                score += 0.06  # Periodic short-lived HTTP(S) reconnection beacon

        # 5. Host process trust context (when live Win32/psutil attribution is available)
        if host_context_known:
            if proc_signed == 0:
                score += 0.14
            if path_class in (1, 2):  # AppData/Local or Temp/Downloads/Public
                score += 0.08
            elif path_class == 0 and proc_signed == 1 and raw_ip == 0 and mad <= 0.05:
                # Benign signed enterprise OS/vendor daemon check (e.g. containerd / windows update)
                if iat_med <= 11.0 and size_mad <= 0.05:
                    score = min(score, 0.35)
        else:
            # Offline PCAP mode has no process signature context; weight network cadence strongly
            if mad <= 0.15 and iqr <= 0.25:
                score += 0.12
            if raw_ip == 1 and mad <= 0.20:
                score += 0.05

        return min(0.992, max(0.002, round(score, 4)))

    def _explain_v1(
        self,
        f: dict[str, float],
        proba: float,
        host_context_known: bool,
    ) -> tuple[list[str], str, str]:
        """Builds human-readable SOC reasons, framework hint, and MITRE ATT&CK alignment."""
        reasons: list[str] = []
        mad = f["iat_mad_ratio"]
        iqr = f["iat_iqr_ratio"]
        skew = f["iat_bowley_skew"]
        size_mad = f["size_mad_ratio"]
        raw_ip = int(f["raw_ip_flag"])
        proc_signed = int(f["proc_signed"])
        path_class = int(f["proc_path_class"])
        iat_med = f["iat_median"]
        conn_burst = f["conn_per_burst"]

        if mad <= 0.15:
            reasons.append(f"Rigid Clockwork IAT Dispersion (MAD={mad:.3f}, Median={iat_med:.1f}s)")
        elif mad <= 0.28:
            reasons.append(f"Jitter-Bounded Periodic Sleep (MAD={mad:.3f}, IQR={iqr:.3f})")

        if abs(skew) <= 0.22 and mad <= 0.25:
            reasons.append(f"Symmetric Jitter Timer Profile (Bowley Skew={skew:+.2f})")

        if size_mad <= 0.12 and mad <= 0.28:
            reasons.append(f"Fixed C2 Heartbeat Payload Size (Size MAD={size_mad:.3f})")

        if raw_ip == 1:
            reasons.append("Direct IP Egress Without Prior DNS Lookup (raw_ip_flag=1)")

        if host_context_known and proc_signed == 0:
            reasons.append("Unsigned PE Binary Executed on Disk (WinVerifyTrust Fail)")

        if host_context_known and path_class in (1, 2):
            zone = "AppData/Local" if path_class == 1 else "Temp/Downloads/Public"
            reasons.append(f"High-Risk Userland Execution Path ({zone})")

        if proba < 0.48:
            return (
                ["Stochastic Human / Organic Traffic Dispersion" if mad > 0.30 else "Expected Vendor Baseline Cadence"],
                "Organic / Benign Traffic",
                "None (Allowlisted Baseline)",
            )

        # Determine C2 / Technique attribution hint (kept crisp for terminal tables & cards)
        if iat_med <= 5.5 and raw_ip == 1:
            hint = "East-West SMB Lateral Pivot"
            mitre = "T1021.002 (SMB) / T1071"
        elif conn_burst <= 0.25 and raw_ip == 1:
            hint = "Sliver mTLS / Raw-IP C2"
            mitre = "T1071.001 (Web) / T1573.002"
        elif conn_burst > 0.25:
            hint = "Cobalt Strike Malleable HTTPS"
            mitre = "T1071.001 (Web) / T1090.004"
        else:
            hint = "Periodic Encrypted C2 Tunnel"
            mitre = "T1071.001 (Web Protocols)"

        return reasons, hint, mitre
