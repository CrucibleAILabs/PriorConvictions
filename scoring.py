#!/usr/bin/env python3
"""
scoring.py -- turn metrics into per-axis, per-profile risk scores.

Reads risk_model.json. No weights, thresholds or severities live in here: the
whole point of the split is that recalibration is a data change.

Two deliberate departures from the grader this replaces:

  * an axis score is a weighted MEAN of its rules, not a sum. The existing
    grader adds uncapped severity points, so more findings always means a
    worse grade -- which is why 19 of 20 subnets come out F and one scored 231
    against an F line of 80. A mean means enabling a signal changes the mix
    rather than inflating the total.

  * seizability and value_decay are scored SEPARATELY. A subnet can be
    unseizable while the owner exits into your bid, or perfectly healthy and
    takeable on Tuesday. Collapsing those into one letter destroys the
    information a buyer actually needs.

A rule that cannot be evaluated is REPORTED, never silently dropped -- a
missing input is a gap in coverage, and a score that hides it is a lie.
"""

from __future__ import annotations

import json
from typing import Any, Optional

import metrics as M


def interpolate(scale: list, x: float) -> float:
    """Piecewise-linear lookup, clamped at both ends.

    Direction is encoded in the scale itself: points are sorted by x, so a
    descending scale (more days -> less risk) works without a separate invert
    flag. One less thing to get backwards.
    """
    pts = sorted(((float(a), float(b)) for a, b in scale), key=lambda p: p[0])
    if x <= pts[0][0]:
        return pts[0][1]
    if x >= pts[-1][0]:
        return pts[-1][1]
    for (x0, y0), (x1, y1) in zip(pts, pts[1:]):
        if x0 <= x <= x1:
            if x1 == x0:
                return y1
            return y0 + (y1 - y0) * (x - x0) / (x1 - x0)
    return pts[-1][1]


def evaluate_rule(name: str, rule: dict, values: dict) -> dict:
    """One rule against one subnet's metrics."""
    out = {"rule": name, "axis": rule.get("axis"), "status": "ok",
           "contribution": None, "value": None}

    gate = rule.get("gated_on")
    if gate is not None and not values.get(gate):
        out["status"] = "gate_closed"
        return out

    key = rule.get("metric")
    if key not in values:
        out["status"] = "metric_missing"
        return out

    raw = values.get(key)
    if raw is None:
        # Some metrics are legitimately null: time_to_seize is null when the
        # strongest entity can never reach the threshold, which is the SAFEST
        # possible state, not a missing reading.
        if rule.get("null_means") == "no_risk":
            out.update(status="null_no_risk", value=None, contribution=0.0)
            return out
        out["status"] = "null_unknown"
        return out

    try:
        x = float(raw)
    except (TypeError, ValueError):
        out["status"] = "not_numeric"
        return out

    norm = rule.get("normalize_by")
    if norm:
        denom = values.get(norm)
        if not denom:
            out["status"] = "normalizer_missing_or_zero"
            return out
        x = x / float(denom)

    out["value"] = x
    out["contribution"] = max(0.0, min(1.0, interpolate(rule["scale"], x)))
    return out


_GRADE_ORDER = ["A", "B", "C", "D", "F"]


def _condition_met(values: dict, cond: dict) -> bool:
    """A condition on an absent or null metric is NOT met.

    Anchors make grades worse, so failing open would invent an F out of a
    missing reading -- the same class of mistake as scoring an unusable rule
    as zero risk.
    """
    v = values.get(cond["metric"])
    if v is None:
        return False
    try:
        if "eq" in cond:
            return v == cond["eq"]
        x = float(v)
    except (TypeError, ValueError):
        return False
    if "gte" in cond and not x >= float(cond["gte"]):
        return False
    if "gt" in cond and not x > float(cond["gt"]):
        return False
    if "lt" in cond and not x < float(cond["lt"]):
        return False
    if "lte" in cond and not x <= float(cond["lte"]):
        return False
    return any(k in cond for k in ("gte", "gt", "lt", "lte"))


def apply_anchors(grade: str, values: dict, cfg: dict, profile: str):
    """Floor a grade at a stated absolute condition.

    Anchors exist so that F means something specific -- 'a rival can take this
    and buying it will not fix that' -- rather than 'worst 5% of whatever
    happens to exist'. They can only make a grade worse; a bad score is never
    rescued by failing to meet one.
    """
    fired = []
    for anchor in (cfg.get("scoring", {}).get("anchors") or []):
        if profile not in (anchor.get("applies_to") or []):
            continue
        conds = anchor.get("all_of") or []
        if conds and all(_condition_met(values, c) for c in conds):
            fired.append({"label": anchor.get("label"), "grade": anchor["grade"],
                          "why": anchor.get("why")})
    if not fired:
        return grade, []
    worst = max(fired, key=lambda a: _GRADE_ORDER.index(a["grade"]))
    if grade is None or _GRADE_ORDER.index(worst["grade"]) > _GRADE_ORDER.index(grade):
        return worst["grade"], fired
    return grade, fired


def score(values: dict, config: Optional[dict] = None) -> dict:
    cfg = config or M.load_config()
    rules = {k: v for k, v in (cfg.get("rules") or {}).items()
             if v.get("enabled", True)}
    evaluated = {k: evaluate_rule(k, r, values) for k, r in rules.items()}

    def bands_for(profile_name: str):
        # Per profile: the purchaser and investor distributions differ enough
        # that one band set mislabels the other (investor p75 = 40.5 against
        # purchaser 48.2).
        by_profile = cfg["scoring"].get("bands_by_profile") or {}
        raw = by_profile.get(profile_name) or cfg["scoring"].get("bands")
        return sorted(((float(t), g) for t, g in raw), key=lambda b: -b[0])

    def grade_for(s: float, bands) -> str:
        for threshold, letter in bands:
            if s >= threshold:
                return letter
        return bands[-1][1]

    out: dict[str, Any] = {"rules": evaluated, "profiles": {}}
    for pname, profile in (cfg.get("profiles") or {}).items():
        weights = profile.get("rule_weights") or {}
        axis_weights = profile.get("axis_weights") or {}
        axes: dict[str, Any] = {}

        for axis in (cfg.get("axes") or {}):
            num = den = 0.0
            used, unusable = [], []
            for rname, ev in evaluated.items():
                if ev["axis"] != axis:
                    continue
                w = float(weights.get(rname, 1.0))
                if ev["contribution"] is None:
                    unusable.append({"rule": rname, "why": ev["status"]})
                    continue
                num += w * ev["contribution"]
                den += w
                used.append({"rule": rname, "weight": w,
                             "contribution": round(ev["contribution"], 4),
                             "value": ev["value"]})
            axes[axis] = {
                "score": round(100.0 * num / den, 1) if den else None,
                "rules_used": sorted(used, key=lambda r: -r["weight"] * r["contribution"]),
                "rules_unusable": unusable,
                "coverage": f"{len(used)}/{len(used) + len(unusable)}",
            }

        scored = [(a, v["score"]) for a, v in axes.items() if v["score"] is not None]
        if scored:
            wsum = sum(float(axis_weights.get(a, 1.0)) for a, _ in scored)
            overall = sum(float(axis_weights.get(a, 1.0)) * s for a, s in scored) / wsum
        else:
            overall = None

        base = (grade_for(overall, bands_for(pname))
                if overall is not None else None)
        final, fired = apply_anchors(base, values, cfg, pname)
        out["profiles"][pname] = {
            "axes": axes,
            "overall": round(overall, 1) if overall is not None else None,
            "grade": final,
            "score_grade": base,
            "anchors_fired": fired,
            "description": profile.get("description"),
        }

    out["model_version"] = cfg.get("version")
    return out


def explain(result: dict, profile: str = "purchaser") -> str:
    """Human-readable breakdown -- what drove the score, and what was missing."""
    p = result["profiles"][profile]
    lines = [f"profile: {profile} -- {p.get('description','')}",
             f"OVERALL {p['overall']}  grade {p['grade']}   (model {result['model_version']})"]
    for a in p.get("anchors_fired") or []:
        arrow = "" if p.get("score_grade") == p["grade"] else f" (score alone: {p['score_grade']})"
        lines.append(f"  ANCHOR {a['label']} -> {a['grade']}{arrow}")
        lines.append(f"    {a['why']}")
    for axis, a in p["axes"].items():
        lines.append(f"\n  {axis}: {a['score']}   coverage {a['coverage']}")
        for r in a["rules_used"]:
            val = r["value"]
            shown = f"{val:,.3f}" if isinstance(val, float) else str(val)
            lines.append(f"     {r['contribution']:>5.2f} x w{r['weight']:<4} "
                         f"{r['rule']:<32} ({shown})")
        for r in a["rules_unusable"]:
            lines.append(f"        --  {r['rule']:<32} [{r['why']}]")
    return "\n".join(lines)
