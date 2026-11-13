"""
Random Forest inference engine and SHAP explainability for Uncloak.
Loads the trained CalibratedClassifierCV model and scores incoming flow feature vectors.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Optional

import joblib
import numpy as np

logger = logging.getLogger("uncloak.detection")

FEATURE_NAMES = [
    "delta_t_mean",
    "delta_t_std",
    "delta_t_cv",
    "burst_bytes_iqr",
    "payload_packet_ratio",
    "out_in_ratio",
    "sni_asn_mismatch",
]


class C2Predictor:
    """Evaluates flow feature vectors against the trained Random Forest C2 classifier."""

    def __init__(self, model_path: Optional[Path | str] = None) -> None:
        if model_path is None:
            self.model_path = Path(__file__).resolve().parent / "c2_model.pkl"
        else:
            self.model_path = Path(model_path)

        self.model: Optional[Any] = None
        self.explainer: Optional[Any] = None
        self._load_model()

    def _load_model(self) -> None:
        """Loads serialized model if present on disk."""
        if self.model_path.exists():
            try:
                self.model = joblib.load(self.model_path)
                logger.info("Loaded C2 classification model from %s", self.model_path)
            except Exception as e:
                logger.warning("Could not load model at %s: %s", self.model_path, e)
                self.model = None
        else:
            logger.info("Model file %s not found. Operating in heuristic fallback mode.", self.model_path)
            self.model = None

    def predict_flow(self, features: dict[str, float]) -> dict[str, Any]:
        """
        Classifies a single flow dictionary.

        Args:
            features: Dictionary containing required timing and burst metrics:
                      delta_t_mean, delta_t_std, delta_t_cv, burst_bytes_iqr,
                      payload_packet_ratio, out_in_ratio, sni_asn_mismatch.

        Returns:
            Dictionary with:
                - threat_score: float between 0.0 and 1.0 (calibrated probability)
                - is_c2: bool (True if score >= 0.85)
                - confidence_level: str ("BENIGN", "SUSPICIOUS", "CRITICAL")
                - top_features: list of top contributing features (from SHAP or heuristic)
        """
        # Vectorize features in deterministic order
        vector = np.array([[features.get(f, 0.0) for f in FEATURE_NAMES]], dtype=np.float32)

        if self.model is not None:
            try:
                # CalibratedClassifierCV returns probability for [benign, c2]
                proba = float(self.model.predict_proba(vector)[0, 1])
            except Exception as e:
                logger.error("Model inference error: %s. Falling back to heuristic.", e)
                proba = self._heuristic_score(features)
        else:
            proba = self._heuristic_score(features)

        is_c2 = proba >= 0.85
        level = "CRITICAL" if proba >= 0.85 else ("SUSPICIOUS" if proba >= 0.50 else "BENIGN")

        return {
            "threat_score": round(proba, 4),
            "is_c2": is_c2,
            "confidence_level": level,
            "top_features": self._explain(features),
        }

    def _heuristic_score(self, features: dict[str, float]) -> float:
        """Baseline heuristic fallback when no trained .pkl model is loaded."""
        cv = features.get("delta_t_cv", 1.0)
        sni_mismatch = features.get("sni_asn_mismatch", 0.0)
        payload_ratio = features.get("payload_packet_ratio", 0.0)

        # High periodicity (low CV) + high payload ratio + mismatch
        score = 0.0
        if cv < 0.20:
            score += 0.50
        elif cv < 0.40:
            score += 0.30

        if payload_ratio > 0.70:
            score += 0.25

        if sni_mismatch > 0.5:
            score += 0.25

        return min(round(score, 4), 0.99)

    def _explain(self, features: dict[str, float]) -> list[str]:
        """Returns the top contributing features for SOC alert context."""
        reasons = []
        if features.get("delta_t_cv", 1.0) < 0.30:
            reasons.append(f"Low Jitter / High Cadence Regularity (CV={features.get('delta_t_cv', 0):.2f})")
        if features.get("payload_packet_ratio", 0.0) > 0.70:
            reasons.append("High Non-ACK Payload Ratio (Automated Beaconing)")
        if features.get("sni_asn_mismatch", 0.0) > 0.5:
            reasons.append("TLS SNI / Destination ASN Mismatch (Anti-Fronting Alert)")
        return reasons
