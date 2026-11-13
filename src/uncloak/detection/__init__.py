"""
Machine Learning detection subsystem for Uncloak.
Houses the trained Random Forest classifier, probability calibration, and SHAP explainability.
"""

from __future__ import annotations

__all__ = ["C2Predictor"]

from uncloak.detection.model import C2Predictor
