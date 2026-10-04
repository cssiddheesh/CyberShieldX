"""AI/Human Text Analyzer: local statistical analysis (PRD section 7.6).

Pure functions - no network, no external models. Measures surface
characteristics associated with AI-generated writing and combines them into
a low/moderate/high/inconclusive AI-likeness band.

Required limitation (always surfaced in reports):
  AI-text detection is probabilistic and cannot establish authorship with certainty.
Never claim definitive authorship.
"""
from __future__ import annotations

import math
import re
from collections import Counter
from typing import Any

from app.models.evidence import Evidence, IndicatorType, ResultOrigin

SOURCE = "Text Analyzer"
SOURCE_TYPE = "local_text_analysis"

REQUIRED_LIMITATION = ("AI-text detection is probabilistic and cannot establish "
                       "authorship with certainty.")

MIN_WORDS = 40
MAX_TEXT = 20000

_SENTENCE_SPLIT = re.compile(r"(?<=[.!?])\s+(?=[A-Z0-9\"'(\[])|\n+")
_WORD = re.compile(r"[A-Za-z0-9]+(?:'[a-z]+)?")

TRANSITION_WORDS = frozenset({
    "moreover", "furthermore", "additionally", "consequently", "therefore",
    "however", "nevertheless", "in conclusion", "in summary", "overall",
    "firstly", "secondly", "lastly", "notably", "crucially", "importantly",
})

# Words strongly over-represented in LLM output (publicly documented "AI tells").
AI_TELL_WORDS = frozenset({
    "delve", "tapestry", "landscape", "realm", "showcase", "showcasing",
    "pivotal", "intricate", "vibrant", "bustling", "moreover", "furthermore",
    "crucial", "essential", "testament", "boast", "nestled", "embark",
    "leverage", "utilize", "comprehensive", "multifaceted",
})

HEDGE_WORDS = frozenset({
    "might", "could", "possibly", "perhaps", "generally", "typically",
    "often", "tends", "suggests", "appears", "seems", "likely",
})


def _sentences(text: str) -> list[str]:
    parts = [s.strip() for s in _SENTENCE_SPLIT.split(text.strip()) if s.strip()]
    return parts or ([text.strip()] if text.strip() else [])


def _paragraphs(text: str) -> list[str]:
    return [p.strip() for p in re.split(r"\n\s*\n", text.strip()) if p.strip()]


def analyze_text(text: str) -> dict[str, Any]:
    """Statistical text analysis. Returns a JSON-serializable dict."""
    text = (text if isinstance(text, str) else "")[:MAX_TEXT]
    words = _WORD.findall(text.lower())
    sentences = _sentences(text)
    paragraphs = _paragraphs(text)
    n_words = len(words)
    n_sent = len(sentences)

    stats: dict[str, Any] = {
        "chars": len(text), "words": n_words, "sentences": n_sent,
        "paragraphs": len(paragraphs),
    }
    indicators: list[dict[str, Any]] = []

    def add(id_: str, title: str, detail: str, severity: str, weight: int, confidence: float):
        indicators.append({"id": id_, "title": title, "detail": detail,
                           "severity": severity, "weight": weight, "confidence": confidence})

    if n_words < MIN_WORDS:
        stats["verdict"] = "inconclusive"
        stats["reason"] = (f"Only {n_words} words: too little text for statistical analysis "
                           f"(minimum {MIN_WORDS}).")
        evidence = [Evidence(text[:500], IndicatorType.TEXT, SOURCE, SOURCE_TYPE,
                             "Text too short for analysis", "info", 0.9,
                             stats["reason"] + " " + REQUIRED_LIMITATION,
                             "", "informational", ResultOrigin.LOCAL)]
        return {"stats": stats, "indicators": [], "likeness": "inconclusive",
                "confidence": 0.9, "evidence": [e.to_dict() for e in evidence],
                "local_weights": []}

    sent_lengths = [len(_WORD.findall(s)) for s in sentences]
    mean_len = sum(sent_lengths) / max(1, len(sent_lengths))
    variance = sum((x - mean_len) ** 2 for x in sent_lengths) / max(1, len(sent_lengths))
    cv = (math.sqrt(variance) / mean_len) if mean_len else 0  # coefficient of variation
    stats["mean_sentence_words"] = round(mean_len, 1)
    stats["sentence_cv"] = round(cv, 3)

    ttr = len(set(words)) / n_words  # type-token ratio
    stats["vocab_diversity"] = round(ttr, 3)

    lowered = text.lower()
    tell_hits = sorted({w for w in AI_TELL_WORDS if re.search(rf"\b{re.escape(w)}\b", lowered)})
    stats["ai_tell_words"] = tell_hits
    hedge_hits = sum(1 for w in HEDGE_WORDS if re.search(rf"\b{re.escape(w)}\b", lowered))
    stats["hedge_density"] = round(hedge_hits / max(1, n_sent), 3)

    # repeated sentences / near-duplicate n-grams
    dup_sentences = len(sent_lengths) - len({s.lower().strip() for s in sentences})
    bigrams = Counter(zip(words, words[1:]))
    top_bigram_share = (bigrams.most_common(1)[0][1] / max(1, len(words) - 1)) if len(words) > 1 else 0
    stats["duplicate_sentences"] = dup_sentences

    punct_total = len(re.findall(r"[!?;:,\"'()\-–—…]", text))
    stats["punct_per_100_words"] = round(100 * punct_total / n_words, 1)
    exclaim = len(re.findall(r"!", text))
    emdash = len(re.findall(r"[—–]", text))

    first_person = len(re.findall(r"\b(i|me|my|mine|we|us|our|ours)\b", lowered))
    stats["first_person_per_100"] = round(100 * first_person / n_words, 1)

    # ---- scoring: each AI-associated trait adds weight (0-100 scale) ----
    score = 0
    if cv < 0.35 and n_sent >= 4:
        score += 20
        add("uniform_sentences", f"Unusually uniform sentences (variation {cv:.2f})",
            "Human writing usually bursts - short punchy sentences mixed with long ones. "
            "Machine text tends toward metronomic regularity.", "medium", 20, 0.6)
    if ttr < 0.35 and n_words >= 100:
        score += 15
        add("low_diversity", f"Low vocabulary diversity ({ttr:.2f})",
            "A narrow word pool over a long passage suggests templated or model-generated prose.",
            "medium", 15, 0.55)
    if tell_hits:
        pts = min(30, 8 + 5 * len(tell_hits))
        if len(tell_hits) >= 10:
            # breadth bonus: many DISTINCT model-favoured words is a stronger
            # signal than one repeated buzzword
            pts = min(40, pts + 10)
        score += pts
        add("ai_tells", f"Characteristic AI word choices ({', '.join(tell_hits[:5])})",
            "These words appear far more often in LLM output than in typical human writing. "
            "Individually meaningless; together they are a recognised signal.", "medium", pts, 0.6)
    if dup_sentences or top_bigram_share > 0.06:
        score += 12
        add("repetition", "Noticeable repetition",
            "Repeated sentences or heavily reused phrases occur in both low-effort human text "
            "and unedited model output.", "low", 12, 0.5)
    if emdash >= max(2, n_sent // 4):
        score += 8
        add("emdash_style", "Heavy em-dash use",
            "Frequent em-dashes are a stylistic tic of several popular chat models.", "low", 8, 0.45)
    if stats["hedge_density"] > 0.8:
        score += 8
        add("hedging", "Heavy hedging language",
            "Stacks of 'might', 'typically', 'suggests' read as model-style caution.", "low", 8, 0.45)
    if stats["first_person_per_100"] < 0.3 and n_words >= 150:
        score += 7
        add("impersonal", "Almost no first-person voice",
            "Long human passages usually reveal a speaker; sustained impersonality is model-typical.",
            "low", 7, 0.4)
    if mean_len > 28:
        score += 10
        add("long_sentences", f"Very long average sentences ({mean_len:.0f} words)",
            "Unbroken complex sentences across a whole passage are more machine-typical than human.",
            "low", 10, 0.45)

    score = max(0, min(100, score))
    if score >= 55:
        likeness = "high"
    elif score >= 30:
        likeness = "moderate"
    else:
        likeness = "low"
    confidence = 0.55 + min(0.3, n_words / 2000)  # more text -> more confidence, capped
    confidence = round(min(0.85, confidence), 3)

    stats["ai_score"] = score
    stats["verdict"] = likeness

    evidence = [Evidence(
        text[:500], IndicatorType.TEXT, SOURCE, SOURCE_TYPE,
        item["title"], item["severity"], item["confidence"],  # type: ignore[arg-type]
        item["detail"] + " " + REQUIRED_LIMITATION,
        "", "detected", ResultOrigin.LOCAL) for item in indicators]
    if not indicators:
        evidence.append(Evidence(
            text[:500], IndicatorType.TEXT, SOURCE, SOURCE_TYPE,
            "No strong AI-like characteristics", "info", confidence,
            "Sentence rhythm, vocabulary and style vary the way human writing usually does. "
            + REQUIRED_LIMITATION, "", "informational", ResultOrigin.LOCAL))

    return {"stats": stats, "indicators": indicators, "likeness": likeness,
            "confidence": confidence, "text_excerpt": text[:500],
            "evidence": [e.to_dict() for e in evidence],
            "local_weights": [{"id": i["id"], "weight": i["weight"], "severity": i["severity"]}
                              for i in indicators]}
