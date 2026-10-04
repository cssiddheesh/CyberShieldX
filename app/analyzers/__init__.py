"""Analyzer package. Framework-agnostic: no Flask imports."""
from app.analyzers.phishing import analyze_url

__all__ = ["analyze_url"]
