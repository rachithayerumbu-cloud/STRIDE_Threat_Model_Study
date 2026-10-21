"""
Risk Calculator
===============
Computes a risk level for each threat based on likelihood and impact scores.
Uses a simple 3x3 risk matrix (Low/Medium/High for each axis).
"""

from typing import List, Dict, Any

# Risk matrix: risk_matrix[likelihood][impact] -> risk_level
_SCORE = {"Low": 1, "Medium": 2, "High": 3}

_RISK_MATRIX = {
    (1, 1): "Low",
    (1, 2): "Low",
    (1, 3): "Medium",
    (2, 1): "Low",
    (2, 2): "Medium",
    (2, 3): "High",
    (3, 1): "Medium",
    (3, 2): "High",
    (3, 3): "High",
}


def calculate_risk(likelihood: str, impact: str) -> str:
    """Return Low / Medium / High risk level from likelihood and impact strings."""
    l_score = _SCORE.get(likelihood, 2)
    i_score = _SCORE.get(impact, 2)
    return _RISK_MATRIX.get((l_score, i_score), "Medium")


def enrich_threats(threats: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Add a 'risk_level' key to every threat dict and return the enriched list."""
    for threat in threats:
        threat["risk_level"] = calculate_risk(
            threat.get("likelihood", "Medium"),
            threat.get("impact", "Medium"),
        )
    return threats


def build_summary(threats: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Build a summary dictionary from a list of enriched threats.

    Returns counts by risk level, counts by STRIDE category, and the
    single highest-risk category.
    """
    risk_counts: Dict[str, int] = {"Low": 0, "Medium": 0, "High": 0}
    category_counts: Dict[str, int] = {}

    for threat in threats:
        rl = threat.get("risk_level", "Medium")
        risk_counts[rl] = risk_counts.get(rl, 0) + 1

        cat = threat.get("category", "Unknown")
        category_counts[cat] = category_counts.get(cat, 0) + 1

    highest_risk_category = (
        max(category_counts, key=category_counts.get)
        if category_counts
        else "N/A"
    )

    return {
        "total_threats": len(threats),
        "risk_counts": risk_counts,
        "category_counts": category_counts,
        "highest_risk_category": highest_risk_category,
    }
