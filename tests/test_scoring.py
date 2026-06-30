"""Scoring engine: determinism, dimension behaviour, combos, config override."""

from posturekit import (
    exposure_score,
    sensitive_score,
    retention_score,
    score_resource,
    score_batch,
    summarize,
)


def test_exposure_monotonic():
    levels = ["owner_only", "internal", "guest", "external", "org_wide", "anyone"]
    scores = [exposure_score(lv) for lv in levels]
    assert scores == sorted(scores)
    assert scores[0] == 0 and scores[-1] == 100


def test_exposure_normalises_casing_and_spacing():
    assert exposure_score("Org-Wide") == exposure_score("org_wide")
    assert exposure_score("Anyone") == 100
    assert exposure_score(None) == 0
    assert exposure_score("nonsense") == 0


def test_sensitive_floor_and_volume_ramp():
    # One hit -> floor fraction of the class ceiling; saturates toward ceiling.
    one = sensitive_score(["pii"], hit_count=1)
    many = sensitive_score(["pii"], hit_count=100000)
    assert 0 < one < many <= 75  # pii ceiling is 75
    # Most-severe class wins.
    assert sensitive_score(["confidential", "credentials"], 50) == \
        sensitive_score(["credentials"], 50)
    assert sensitive_score([], 999) == 0.0


def test_retention_buckets():
    assert retention_score(0.5) == 10
    assert retention_score(2) == 35
    assert retention_score(4) == 65
    assert retention_score(9) == 100
    assert retention_score(None) == 0.0


def test_score_resource_is_deterministic():
    sig = {"exposure_level": "anyone", "classifications": ["credentials", "pii"],
           "sensitive_hit_count": 4200, "age_years": 9}
    a = score_resource(sig)
    b = score_resource(sig)
    assert a == b
    assert a["risk_level"] == "Critical"
    assert a["remediation_priority"] == "P1"
    # The trifecta should fire and replace the two pairwise combos.
    assert "sensitive_stale_and_broad" in a["risk_combinations"]
    assert "sensitive_and_broad_exposure" not in a["risk_combinations"]


def test_combo_boost_raises_score():
    base = {"exposure_level": "org_wide", "classifications": ["financial"],
            "sensitive_hit_count": 75, "age_years": 2}
    profile = score_resource(base)
    assert profile["combo_boost"] >= 8  # sensitive + broad exposure fired
    assert profile["risk_score"] == round(profile["base_score"] + profile["combo_boost"], 1)


def test_clean_resource_is_low():
    profile = score_resource({"exposure_level": "owner_only",
                              "classifications": [], "age_years": 0.5})
    assert profile["risk_level"] == "Low"
    assert profile["recommended_action"] == "No Action"
    assert profile["risk_combinations"] == []


def test_recommended_action_precedence():
    # An exception on file short-circuits everything.
    assert score_resource({"exposure_level": "anyone",
                           "classifications": ["pci"], "sensitive_hit_count": 9,
                           "has_exception": True})["recommended_action"] == "Exception Management"
    # Broad + sensitive via delegation -> delegation cleanup.
    assert score_resource({"exposure_level": "org_wide",
                           "classifications": ["pii"], "sensitive_hit_count": 9,
                           "via_delegation": True})["recommended_action"] == "Delegation Cleanup"


def test_config_override_changes_bands():
    sig = {"exposure_level": "internal", "classifications": ["confidential"],
           "sensitive_hit_count": 5, "age_years": 2}
    default = score_resource(sig)
    strict = score_resource(sig, config={"bands": [
        {"min_score": 20, "level": "Critical", "priority": "P1", "sla_days": 1},
        {"min_score": 0, "level": "Low", "priority": "P4", "sla_days": 180},
    ]})
    assert default["risk_level"] != strict["risk_level"]
    assert strict["risk_level"] == "Critical"


def test_summarize_tallies():
    rows = [
        {"exposure_level": "anyone", "classifications": ["credentials"],
         "sensitive_hit_count": 5000, "age_years": 9},
        {"exposure_level": "owner_only", "classifications": [], "age_years": 0.2},
    ]
    summary = summarize(score_batch(rows))
    assert summary["total"] == 2
    assert summary["by_level"]["Critical"] == 1
    assert summary["by_level"]["Low"] == 1
