"""Data-security-posture risk scoring engine.

Turns the three correlated signal families a DSPM correlation layer extracts per
resource (a mailbox, folder, site, drive, share, …) into a single risk profile:

    Exposure    — how broadly the resource is accessible (owner-only ... anyone)
    Sensitive   — what sensitive data lives in it, and how much of it
    Retention   — how old / stale the content is

The composite model is a weighted blend:

    risk_score = 0.40 * exposure + 0.40 * sensitive + 0.20 * retention

with high-risk *combinations* (sensitive data + broad exposure, or sensitive +
long retention + broad exposure) materially boosting the score. The weights, the
per-dimension scales, the score-to-level bands, the SLAs and the remediation
action mapping are all driven by a single ``CONFIG`` dict, and every public
function accepts a ``config`` override, so the model stays configurable.

The defaults below (band cutoffs, SLA days, priority labels, action precedence)
are sensible starting points — override ``CONFIG`` to match your own risk matrix.
The engine is intentionally pure (no I/O, no DB) so it can be unit-tested and
reused unchanged across resource types that share this exposure / sensitive /
retention framework.
"""

from __future__ import annotations

import copy
import math
from typing import Any, Dict, Iterable, List, Optional

# ---------------------------------------------------------------------------
# Configurable model
# ---------------------------------------------------------------------------

CONFIG: Dict[str, Any] = {
    # Composite blend. Must sum to 1.0 (normalised defensively at score time).
    "weights": {
        "exposure": 0.40,
        "sensitive": 0.40,
        "retention": 0.20,
    },

    # Exposure dimension -> normalised 0..100. Ordered least to most exposed.
    "exposure_levels": {
        "owner_only": 0,
        "internal": 30,
        "guest": 55,
        "external": 70,
        "org_wide": 85,
        "anyone": 100,
    },

    # Sensitive dimension. Each classification carries a severity ceiling (0..100);
    # the resource's sensitive score is the highest-severity class present, scaled
    # up toward that ceiling by hit volume (a little data = floor, a lot = ceiling).
    "sensitive_classes": {
        "credentials": 100,
        "pci": 90,
        "phi": 85,
        "pii": 75,
        "financial": 70,
        "confidential": 50,
    },
    # Fraction of the class ceiling applied when only a single hit is present.
    "sensitive_floor_frac": 0.55,
    # Hit count at which the class ceiling is (effectively) reached.
    "sensitive_volume_saturation": 1000,

    # Retention dimension -> normalised 0..100, by age of content (years).
    "retention_buckets": [
        {"max_years": 1, "score": 10, "label": "< 1 Year"},
        {"max_years": 3, "score": 35, "label": "1-3 Years"},
        {"max_years": 6, "score": 65, "label": "3-6 Years"},
        {"max_years": None, "score": 100, "label": "6+ Years"},
    ],
    "stale_years": 6,  # STALE: content last modified this many years ago or more.

    # High-risk combination boosts. Applied additively to the composite (capped at
    # 100). Each fired combo is recorded so a downstream narrative can cite it.
    "combo_boosts": {
        "sensitive_and_broad_exposure": 8,     # sensitive + org-wide/anyone
        "sensitive_and_stale": 6,              # sensitive + stale
        "sensitive_stale_and_broad": 14,       # the trifecta (replaces the two above)
        "high_volume_sensitive_and_broad": 10, # lots of sensitive hits + broad access
    },
    "broad_exposure_levels": {"org_wide", "anyone", "guest", "external"},
    "high_volume_hits": 100,

    # Bands — score -> level. Override cutoffs to match your risk matrix.
    "bands": [
        {"min_score": 80, "level": "Critical", "priority": "P1", "sla_days": 7},
        {"min_score": 60, "level": "High", "priority": "P2", "sla_days": 30},
        {"min_score": 35, "level": "Medium", "priority": "P3", "sla_days": 90},
        {"min_score": 0, "level": "Low", "priority": "P4", "sla_days": 180},
    ],
}

# Canonical remediation actions.
ACTION_PERMISSION_REMOVAL = "Permission Removal"
ACTION_DELEGATION_CLEANUP = "Delegation Cleanup"
ACTION_MAIL_FLOW_REVIEW = "Mail Flow Review"
ACTION_FORWARDING_REVIEW = "Forwarding Review"
ACTION_CONTENT_CLEANUP = "Content Cleanup"
ACTION_RETENTION_ACTION = "Retention Action"
ACTION_EXCEPTION_MGMT = "Exception Management"
ACTION_NONE = "No Action"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _cfg(config: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Return the effective config (caller override deep-merged over defaults)."""
    if not config:
        return CONFIG
    merged = copy.deepcopy(CONFIG)
    for key, val in config.items():
        if isinstance(val, dict) and isinstance(merged.get(key), dict):
            merged[key].update(val)
        else:
            merged[key] = val
    return merged


def _clamp(value: float, lo: float = 0.0, hi: float = 100.0) -> float:
    return max(lo, min(hi, value))


def _norm_level(level: Optional[str]) -> str:
    return (level or "").strip().lower().replace("-", "_").replace(" ", "_")


# ---------------------------------------------------------------------------
# Per-dimension scoring
# ---------------------------------------------------------------------------

def exposure_score(level: Optional[str], config: Optional[Dict[str, Any]] = None) -> float:
    """Normalise an exposure level (e.g. 'org_wide', 'Anyone') to 0..100."""
    cfg = _cfg(config)
    return float(cfg["exposure_levels"].get(_norm_level(level), 0))


def sensitive_score(
    classifications: Optional[Iterable[str]],
    hit_count: int = 0,
    config: Optional[Dict[str, Any]] = None,
) -> float:
    """Score sensitive-data risk from the classes present and the hit volume.

    Driven by the single most severe classification present; that class's ceiling
    is then approached as hit volume rises (one hit -> floor fraction of the
    ceiling, saturation hits -> the full ceiling).
    """
    cfg = _cfg(config)
    classes = cfg["sensitive_classes"]
    present = [classes[_norm_level(c)] for c in (classifications or [])
               if _norm_level(c) in classes]
    if not present:
        return 0.0
    ceiling = max(present)
    floor = ceiling * cfg["sensitive_floor_frac"]
    if hit_count <= 1:
        frac = 0.0
    else:
        # log-scaled ramp from floor (1 hit) to ceiling (saturation hits)
        sat = max(2, cfg["sensitive_volume_saturation"])
        frac = min(1.0, math.log10(hit_count) / math.log10(sat))
    return _clamp(floor + (ceiling - floor) * frac)


def retention_score(age_years: Optional[float], config: Optional[Dict[str, Any]] = None) -> float:
    """Map content age (years since last modification) to 0..100 via the buckets."""
    cfg = _cfg(config)
    if age_years is None:
        return 0.0
    for bucket in cfg["retention_buckets"]:
        if bucket["max_years"] is None or age_years < bucket["max_years"]:
            return float(bucket["score"])
    return float(cfg["retention_buckets"][-1]["score"])


def retention_bucket(age_years: Optional[float], config: Optional[Dict[str, Any]] = None) -> Optional[str]:
    """Human label for the age bucket."""
    cfg = _cfg(config)
    if age_years is None:
        return None
    for bucket in cfg["retention_buckets"]:
        if bucket["max_years"] is None or age_years < bucket["max_years"]:
            return bucket["label"]
    return cfg["retention_buckets"][-1]["label"]


# ---------------------------------------------------------------------------
# Composite scoring
# ---------------------------------------------------------------------------

def _band_for(score: float, cfg: Dict[str, Any]) -> Dict[str, Any]:
    for band in sorted(cfg["bands"], key=lambda b: b["min_score"], reverse=True):
        if score >= band["min_score"]:
            return band
    return cfg["bands"][-1]


def _combos(signals: Dict[str, Any], has_sensitive: bool, is_broad: bool,
            is_stale: bool, hit_count: int, cfg: Dict[str, Any]) -> List[str]:
    """Identify which high-risk combinations fired (for boost + narrative)."""
    fired: List[str] = []
    high_volume = hit_count >= cfg["high_volume_hits"]
    if has_sensitive and is_broad and is_stale:
        fired.append("sensitive_stale_and_broad")
    else:
        if has_sensitive and is_broad:
            fired.append("sensitive_and_broad_exposure")
        if has_sensitive and is_stale:
            fired.append("sensitive_and_stale")
    if has_sensitive and is_broad and high_volume:
        fired.append("high_volume_sensitive_and_broad")
    return fired


def _recommended_action(signals: Dict[str, Any], is_broad: bool, is_stale: bool,
                        has_sensitive: bool) -> str:
    """Pick the dominant remediation action from the resource's signals."""
    if signals.get("has_exception"):
        return ACTION_EXCEPTION_MGMT
    if signals.get("has_external_forwarding"):
        return ACTION_FORWARDING_REVIEW
    if signals.get("has_mail_flow_rule"):
        return ACTION_MAIL_FLOW_REVIEW
    # Broad exposure on a sensitive resource -> pull the access back first.
    if is_broad and has_sensitive:
        if signals.get("via_delegation"):
            return ACTION_DELEGATION_CLEANUP
        return ACTION_PERMISSION_REMOVAL
    if is_broad:
        return ACTION_DELEGATION_CLEANUP if signals.get("via_delegation") else ACTION_PERMISSION_REMOVAL
    if is_stale and has_sensitive:
        return ACTION_CONTENT_CLEANUP
    if is_stale:
        return ACTION_RETENTION_ACTION
    if has_sensitive:
        return ACTION_PERMISSION_REMOVAL
    return ACTION_NONE


def score_resource(signals: Dict[str, Any], config: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Score a single correlated resource.

    ``signals`` is the canonical, source-agnostic view a correlation layer
    produces per resource. Recognised keys (all optional):

        exposure_level        str  — owner_only|internal|guest|external|org_wide|anyone
        classifications       list — e.g. ['pii', 'financial']
        sensitive_hit_count   int  — total sensitive hits in the resource
        age_years             float— years since last modification
        via_delegation        bool — exposure granted through delegated access
        has_external_forwarding bool
        has_mail_flow_rule    bool
        has_exception         bool — an approved exception is on file

    Returns the resource's full risk profile: the three sub-scores, the weighted
    composite, the level / priority / SLA, the recommended action, and the list
    of high-risk combinations that fired.
    """
    cfg = _cfg(config)

    exp = exposure_score(signals.get("exposure_level"), cfg)
    classes = signals.get("classifications") or []
    hits = int(signals.get("sensitive_hit_count") or 0)
    sen = sensitive_score(classes, hits, cfg)
    age = signals.get("age_years")
    ret = retention_score(age, cfg)

    weights = cfg["weights"]
    wsum = sum(weights.values()) or 1.0
    base = (exp * weights["exposure"]
            + sen * weights["sensitive"]
            + ret * weights["retention"]) / wsum

    has_sensitive = sen > 0
    is_broad = _norm_level(signals.get("exposure_level")) in cfg["broad_exposure_levels"]
    is_stale = age is not None and age >= cfg["stale_years"]

    fired = _combos(signals, has_sensitive, is_broad, is_stale, hits, cfg)
    boost = sum(cfg["combo_boosts"].get(name, 0) for name in fired)

    risk = _clamp(base + boost)
    band = _band_for(risk, cfg)
    action = _recommended_action(signals, is_broad, is_stale, has_sensitive)

    return {
        "exposure_score": round(exp, 1),
        "sensitive_score": round(sen, 1),
        "retention_score": round(ret, 1),
        "base_score": round(base, 1),
        "combo_boost": boost,
        "risk_score": round(risk, 1),
        "risk_level": band["level"],
        "remediation_priority": band["priority"],
        "sla_days": band["sla_days"],
        "recommended_action": action,
        "age_bucket": retention_bucket(age, cfg),
        "is_stale": is_stale,
        "is_broad_exposure": is_broad,
        "has_sensitive": has_sensitive,
        "risk_combinations": fired,
    }


def score_batch(rows: Iterable[Dict[str, Any]], config: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
    """Score many resources; returns each input row merged with its risk profile."""
    cfg = _cfg(config)
    out: List[Dict[str, Any]] = []
    for row in rows:
        profile = score_resource(row, cfg)
        merged = dict(row)
        merged.update(profile)
        out.append(merged)
    return out


def summarize(scored: Iterable[Dict[str, Any]]) -> Dict[str, Any]:
    """Roll a scored batch up into a level distribution + combination tally."""
    counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    combos: Dict[str, int] = {}
    total = 0
    for row in scored:
        total += 1
        counts[row.get("risk_level", "Low")] = counts.get(row.get("risk_level", "Low"), 0) + 1
        for c in row.get("risk_combinations", []):
            combos[c] = combos.get(c, 0) + 1
    return {"total": total, "by_level": counts, "by_combination": combos}
