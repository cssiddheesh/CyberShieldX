"""Correlation package: evidence merging plus the transparent risk model."""
from app.correlation.engine import correlate, note_provider_gaps
from app.correlation.risk import assess_risk

__all__ = ["correlate", "note_provider_gaps", "assess_risk"]
