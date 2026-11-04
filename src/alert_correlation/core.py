"""Small, dependency-free AIT-ADS alert correlation baseline.

Labels are weak pair labels: two alerts are positive when both timestamps fall
inside the dataset's labeled attack-phase intervals in the same scenario.
This is a reproducible proxy for correlation, not independent analyst-confirmed
pairwise ground truth.
"""
from __future__ import annotations

import csv
import json
import math
import zipfile
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

FEATURES = ["same_host", "same_detector", "same_signature", "gap_le_10s", "gap_le_60s"]
SCENARIOS = ["shaw", "wardbeck", "russellmitchell"]
TRAIN_SCENARIOS = ["shaw", "wardbeck"]
TEST_SCENARIOS = ["russellmitchell"]
MAX_HISTORY = 50
MAX_CANDIDATES = 5
MAX_GAP_SECONDS = 1800
BETA_ALPHA = 1.0
BETA_BETA = 1.0


def _timestamp(record, sensor):
    if sensor == "aminer":
        values = record.get("LogData", {}).get("Timestamps", [])
        return float(values[0]) if values else None
    value = record.get("@timestamp")
    if not value:
        return None
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc).timestamp()


def _normalize(record, scenario, sensor, line_number, phase_intervals):
    if sensor == "wazuh":
        ts = _timestamp(record, sensor)
        rule = record.get("rule", {})
        groups = rule.get("groups", [])
        location = str(record.get("location", ""))
        detector = "Suricata" if "suricata" in (location + " " + " ".join(groups)).lower() else "Wazuh"
        host = (record.get("agent", {}).get("ip")
                or record.get("predecoder", {}).get("hostname") or "")
        signature = str(rule.get("id") or record.get("decoder", {}).get("name") or "unknown")
        severity = int(rule.get("level", 0) or 0)
        message = str(rule.get("description") or record.get("full_log", ""))
    else:
        ts = _timestamp(record, sensor)
        component = record.get("AnalysisComponent", {})
        detector = "AMiner"
        host = str(record.get("AMiner", {}).get("ID", ""))
        signature = str(component.get("AnalysisComponentIdentifier") or component.get("AnalysisComponentName") or "unknown")
        severity = 0
        message = str(component.get("Message") or component.get("AnalysisComponentName") or "")
    if ts is None:
        return None
    phase = ""
    for start, end, name in phase_intervals:
        if start <= ts <= end:
            phase = name
            break
    return {
        "scenario": scenario,
        "event_id": f"{scenario}:{sensor}:{line_number}",
        "timestamp_epoch": f"{ts:.6f}",
        "timestamp_utc": datetime.fromtimestamp(ts, timezone.utc).isoformat(),
        "detector": detector,
        "host": host,
        "signature": signature,
        "severity": severity,
        "message": message[:240].replace("\n", " "),
        "attack_phase": phase,
        "is_attack": int(bool(phase)),
    }


def preprocess_ait_ads(zip_path, labels_path, output_csv, scenarios=None):
    """Normalize selected AIT-ADS JSONL scenario files and attach phase labels."""
    scenarios = list(scenarios or SCENARIOS)
    intervals = defaultdict(list)
    with open(labels_path, newline="", encoding="utf-8-sig") as f:
        for row in csv.DictReader(f):
            intervals[row["scenario"]].append((float(row["start"]), float(row["end"]), row["attack"]))
    for scenario in intervals:
        intervals[scenario].sort()
    output_csv = Path(output_csv)
    output_csv.parent.mkdir(parents=True, exist_ok=True)
    fields = ["scenario", "event_id", "timestamp_epoch", "timestamp_utc", "detector", "host", "signature", "severity", "message", "attack_phase", "is_attack"]
    counts = defaultdict(lambda: {"alerts": 0, "attack_phase": 0})
    with zipfile.ZipFile(zip_path) as archive, open(output_csv, "w", newline="", encoding="utf-8") as out:
        writer = csv.DictWriter(out, fieldnames=fields)
        writer.writeheader()
        names = set(archive.namelist())
        for scenario in scenarios:
            for sensor in ("aminer", "wazuh"):
                member = f"{scenario}_{sensor}.json"
                if member not in names:
                    raise FileNotFoundError(f"Missing {member} in {zip_path}")
                with archive.open(member) as stream:
                    for line_no, raw in enumerate(stream, 1):
                        record = json.loads(raw)
                        item = _normalize(record, scenario, sensor, line_no, intervals[scenario])
                        if item is None:
                            continue
                        writer.writerow(item)
                        counts[scenario]["alerts"] += 1
                        counts[scenario]["attack_phase"] += item["is_attack"]
    return dict(counts)


def load_alerts(csv_path):
    alerts = []
    with open(csv_path, newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            row["timestamp_epoch"] = float(row["timestamp_epoch"])
            row["severity"] = int(row["severity"])
            row["is_attack"] = int(row["is_attack"])
            alerts.append(row)
    return alerts


def pair_features(previous, current):
    gap = max(0.0, current["timestamp_epoch"] - previous["timestamp_epoch"])
    return {
        "same_host": int(bool(previous["host"]) and previous["host"] == current["host"]),
        "same_detector": int(previous["detector"] == current["detector"]),
        "same_signature": int(previous["signature"] == current["signature"]),
        "gap_le_10s": int(gap <= 10),
        "gap_le_60s": int(gap <= 60),
    }


def select_history_candidates(current, previous_alerts, max_candidates=MAX_CANDIDATES):
    """Select a small, diverse history set using observable alert fields only."""
    found = {"recent": None, "same_host": None, "different_signature": None,
             "different_detector": None, "same_signature": None}
    for old in reversed(previous_alerts):
        if found["recent"] is None:
            found["recent"] = old
        if found["same_host"] is None and current["host"] and old["host"] == current["host"]:
            found["same_host"] = old
        if found["different_signature"] is None and old["signature"] != current["signature"]:
            found["different_signature"] = old
        if found["different_detector"] is None and old["detector"] != current["detector"]:
            found["different_detector"] = old
        if found["same_signature"] is None and old["signature"] == current["signature"]:
            found["same_signature"] = old
        if all(value is not None for value in found.values()):
            break
    selected = []
    for key in found:
        match = found[key]
        if match is not None and all(match["event_id"] != prior["event_id"] for prior in selected):
            selected.append(match)
        if len(selected) >= max_candidates:
            break
    return selected


def iter_candidate_pairs(alerts, scenarios, max_history=MAX_HISTORY, max_gap_seconds=MAX_GAP_SECONDS):
    """Yield bounded history pairs; candidate generation never uses phase labels."""
    grouped = defaultdict(list)
    wanted = set(scenarios)
    for alert in alerts:
        if alert["scenario"] in wanted:
            grouped[alert["scenario"]].append(alert)
    for scenario in sorted(wanted):
        stream = sorted(grouped.get(scenario, []), key=lambda a: (a["timestamp_epoch"], a["event_id"]))
        for i, current in enumerate(stream):
            prior = stream[max(0, i - max_history):i]
            prior = [old for old in prior
                     if 0 <= current["timestamp_epoch"] - old["timestamp_epoch"] <= max_gap_seconds]
            for previous in select_history_candidates(current, prior):
                x = pair_features(previous, current)
                # Weak pair label: both alerts fall in attack-phase windows.
                # This is a scenario-level proxy, not an analyst-confirmed pair verdict.
                y = int(bool(previous["attack_phase"]) and bool(current["attack_phase"]))
                yield {"previous_id": previous["event_id"], "current_id": current["event_id"],
                       "scenario": scenario, "features": x, "label": y}


def fit_beta_bernoulli(alerts, train_scenarios):
    """Fit a Bayesian Bernoulli Naive Bayes pair model with Beta(1,1) priors."""
    counts = {"0": {"n": 0, "ones": {f: 0 for f in FEATURES}},
              "1": {"n": 0, "ones": {f: 0 for f in FEATURES}}}
    for pair in iter_candidate_pairs(alerts, train_scenarios):
        bucket = counts[str(pair["label"])]
        bucket["n"] += 1
        for name in FEATURES:
            bucket["ones"][name] += pair["features"][name]
    if not counts["0"]["n"] or not counts["1"]["n"]:
        raise ValueError("Training scenarios must produce both linked and unlinked pairs.")
    return {"features": FEATURES, "alpha": BETA_ALPHA, "beta": BETA_BETA,
            "class_counts": {key: value["n"] for key, value in counts.items()},
            "feature_ones": {key: value["ones"] for key, value in counts.items()},
            "train_scenarios": list(train_scenarios),
            "label_definition": "Both alerts fall inside labeled attack-phase windows in the same scenario and within the history window (weak pair label; not independent analyst-confirmed linkage).",
            "max_history": MAX_HISTORY, "max_candidates": MAX_CANDIDATES,
            "max_gap_seconds": MAX_GAP_SECONDS}


def score_pair(features, model):
    """Return posterior-predictive probability that a candidate pair is linked."""
    alpha, beta = model["alpha"], model["beta"]
    n0, n1 = model["class_counts"]["0"], model["class_counts"]["1"]
    prior1 = (n1 + alpha) / (n0 + n1 + alpha + beta)
    prior0 = 1.0 - prior1
    logp = {"0": math.log(prior0), "1": math.log(prior1)}
    for cls in ("0", "1"):
        n = model["class_counts"][cls]
        for name in model["features"]:
            theta = (model["feature_ones"][cls][name] + alpha) / (n + alpha + beta)
            x = int(features[name])
            likelihood = theta if x else 1.0 - theta
            logp[cls] += math.log(max(likelihood, 1e-12))
    difference = logp["1"] - logp["0"]
    return 1.0 / (1.0 + math.exp(-max(min(difference, 700), -700)))


def evaluate(alerts, test_scenarios, model, threshold=0.5):
    labels, scores = [], []
    for pair in iter_candidate_pairs(alerts, test_scenarios):
        labels.append(pair["label"])
        scores.append(score_pair(pair["features"], model))
    n = len(labels)
    tp = sum(y == 1 and s >= threshold for y, s in zip(labels, scores))
    fp = sum(y == 0 and s >= threshold for y, s in zip(labels, scores))
    fn = sum(y == 1 and s < threshold for y, s in zip(labels, scores))
    tn = n - tp - fp - fn
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    positives = sum(labels); negatives = n - positives
    ranked = sorted(zip(scores, labels), reverse=True)
    seen_pos = 0; seen = 0; ap_sum = 0.0
    for _, y in ranked:
        seen += 1
        if y:
            seen_pos += 1; ap_sum += seen_pos / seen
    average_precision = ap_sum / positives if positives else 0.0
    # Mann-Whitney rank AUC with tied scores receiving half credit.
    ranked_asc = sorted(zip(scores, labels), key=lambda x: x[0])
    neg_before = 0; concordant = 0.0; k = 0
    while k < len(ranked_asc):
        j = k + 1
        while j < len(ranked_asc) and ranked_asc[j][0] == ranked_asc[k][0]: j += 1
        group_pos = sum(y for _, y in ranked_asc[k:j]); group_neg = (j-k)-group_pos
        concordant += group_pos * (neg_before + 0.5 * group_neg)
        neg_before += group_neg; k = j
    roc_auc = concordant / (positives * negatives) if positives and negatives else 0.0
    return {"threshold": threshold, "candidate_pairs": n, "positive_pairs": positives,
            "precision": precision, "recall": recall, "F1": f1,
            "PR_AUC_average_precision": average_precision, "ROC_AUC": roc_auc,
            "confusion_matrix": {"tn": tn, "fp": fp, "fn": fn, "tp": tp},
            "test_scenarios": list(test_scenarios),
            "interpretation": "Exploratory performance against phase-derived weak pair labels, not analyst-confirmed incident links."}


def posterior_feature_table(model):
    result = []
    for feature in model["features"]:
        row = {"feature": feature}
        for cls in ("0", "1"):
            n = model["class_counts"][cls]
            row[f"P(feature=1 | class={cls})"] = (model["feature_ones"][cls][feature] + model["alpha"]) / (n + model["alpha"] + model["beta"])
        result.append(row)
    return result


def save_json(path, obj):
    path = Path(path); path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2), encoding="utf-8")


def stream_correlator(model, threshold=0.5):
    """Create an in-memory service scorer; input alerts must be normalized."""
    history = defaultdict(list)
    def score_alert(alert):
        scenario = alert.get("scenario", "live")
        ts = float(alert["timestamp_epoch"])
        stream = history[scenario]
        while stream and ts - float(stream[0]["timestamp_epoch"]) > model["max_gap_seconds"]:
            stream.pop(0)
        recent = [old for old in stream if 0 <= ts - float(old["timestamp_epoch"]) <= model["max_gap_seconds"]]
        ranked = []
        for previous in select_history_candidates(alert, recent, model["max_candidates"]):
            prob = score_pair(pair_features(previous, alert), model)
            if prob >= threshold:
                ranked.append({"alert_id": previous["event_id"], "correlation_probability": round(prob, 4)})
        stream.append(alert)
        if len(stream) > model["max_history"]:
            del stream[:-model["max_history"]]
        return {"alert_id": alert["event_id"], "correlation_probability": max((x["correlation_probability"] for x in ranked), default=0.0),
                "related_to": ranked, "correlated": bool(ranked), "threshold": threshold}
    return score_alert


def select_threshold_by_scenario_cv(alerts, train_scenarios):
    """Choose a simple F1 threshold from leave-one-scenario-out training predictions."""
    train_scenarios = list(train_scenarios)
    if len(train_scenarios) < 2:
        raise ValueError("At least two training scenarios are required for scenario-level threshold selection.")
    oof = []
    for held_out in train_scenarios:
        fold_train = [s for s in train_scenarios if s != held_out]
        fold_model = fit_beta_bernoulli(alerts, fold_train)
        for pair in iter_candidate_pairs(alerts, [held_out]):
            oof.append((pair["label"], score_pair(pair["features"], fold_model)))
    best = {"threshold": 0.5, "F1": -1.0, "precision": 0.0, "recall": 0.0}
    for step in range(1, 51):
        threshold = step / 100
        tp = sum(y == 1 and score >= threshold for y, score in oof)
        fp = sum(y == 0 and score >= threshold for y, score in oof)
        fn = sum(y == 1 and score < threshold for y, score in oof)
        precision = tp / (tp + fp) if tp + fp else 0.0
        recall = tp / (tp + fn) if tp + fn else 0.0
        f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
        if f1 > best["F1"]:
            best = {"threshold": threshold, "F1": f1, "precision": precision, "recall": recall}
    best["oof_pairs"] = len(oof)
    best["method"] = "Leave-one-scenario-out predictions within training scenarios; maximize F1 on a fixed 0.01 threshold grid."
    return best
