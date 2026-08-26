"""Incident risk scoring: composite of ML scores and behavioral signals."""

import numpy as np
import pandas as pd

SEVERITY_THRESHOLDS = {
    "critical": 0.85,
    "high": 0.60,
    "medium": 0.35,
    "low": 0.0,
}


def score_incident(
    events: pd.DataFrame,
    attack_probability: float,
    anomaly_score: float | None = None,
) -> dict:
    """Compute a composite risk score for a correlated event group.

    Signals (each 0..1):
      - failed_login_ratio, external_contact, rare_process_present,
        sensitive_file_access, privilege_change, data_volume_zscore
    Final risk = weighted blend of ML probability and signal evidence.
    """
    auth = events[events["event_type"] == "authentication"]
    failed_ratio = float((auth["action"] == "login_failure").mean()) if len(auth) else 0.0
    has_priv_esc = int((events["event_type"] == "privilege_change").any())
    files = events[events["event_type"] == "file_access"]
    sensitive = int(
        files["file_path"]
        .fillna("")
        .str.contains("locked|payroll|employee_records|source_archive", case=False)
        .any()
    )
    dst_ips = events["dst_ip"].dropna().astype(str)
    external = (
        float((~dst_ips.str.startswith(("10.", "192.168.", "172."))).mean())
        if len(dst_ips)
        else 0.0
    )
    bytes_out = pd.to_numeric(events.get("bytes_transferred"), errors="coerce").fillna(0).sum()
    volume_signal = float(np.tanh(np.log1p(bytes_out) / 25.0))  # ~1 around >10^9 bytes
    proc = events["process"].dropna().astype(str).str.lower()
    rare_process = int(
        proc.str.contains("encrypt|mimikatz|net_scan|powershell|cmd", regex=True).any()
    )

    signals = {
        "failed_login_ratio": round(failed_ratio, 3),
        "external_contact": round(external, 3),
        "rare_process_present": rare_process,
        "sensitive_file_access": sensitive,
        "privilege_change": has_priv_esc,
        "data_volume": round(volume_signal, 3),
        "n_events": len(events),
    }

    evidence_boost = (
        0.15 * failed_ratio
        + 0.15 * external
        + 0.12 * rare_process
        + 0.12 * sensitive
        + 0.12 * has_priv_esc
        + 0.10 * volume_signal
    )
    risk = 0.60 * attack_probability + 0.40 * min(evidence_boost / 0.76, 1.0)
    if anomaly_score is not None:
        risk = 0.80 * risk + 0.20 * anomaly_score

    severity_label = next(
        (name for name, threshold in SEVERITY_THRESHOLDS.items() if risk >= threshold),
        "low",
    )
    return {
        "risk_score": round(float(risk), 4),
        "severity_label": severity_label,
        "signals": signals,
    }
