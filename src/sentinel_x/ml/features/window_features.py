"""Windowed feature engineering over canonical event streams.

Aggregates events per host-minute bucket and computes rolling-window
behavioral features. Produces a tabular dataset for classical ML models.
"""

from typing import Any

import numpy as np
import pandas as pd

from sentinel_x.common.netutil import is_internal_ip

SENSITIVE_FILE_PATTERNS = ("payroll", "employee_records", "source_archive", ".locked")

WINDOW_MINUTES = 5


def _entropy(series: pd.Series) -> float:
    counts = series.value_counts()
    if len(counts) <= 1:
        return 0.0
    probs = counts / counts.sum()
    return float(-(probs * np.log2(probs)).sum())


def build_host_minute_features(events: pd.DataFrame) -> pd.DataFrame:
    """Aggregate canonical events into host-minute behavioral feature rows.

    Args:
        events: DataFrame with canonical SecurityEvent columns.

    Returns:
        DataFrame with one row per (host, minute) plus label columns.
    """
    df = events.copy()
    df["timestamp"] = pd.to_datetime(df["timestamp"], utc=True)
    if df.empty:
        return pd.DataFrame(columns=["host", "minute", "label_attack"])
    df = df.sort_values("timestamp")
    df["minute"] = df["timestamp"].dt.floor("min")

    # Normalize nullable text fields for safe grouping
    for col in ("host", "src_ip", "dst_ip", "user", "process"):
        if col not in df.columns:
            df[col] = None
        df[col] = df[col].fillna("unknown").astype(str)

    is_external_dst = ~df["dst_ip"].map(is_internal_ip)
    df["_external_dst"] = np.where(df["event_type"] == "network_connection", is_external_dst, False)

    sensitive_hit = (
        df["file_path"]
        .fillna("")
        .str.lower()
        .apply(lambda p: any(pat in p for pat in SENSITIVE_FILE_PATTERNS))
    )
    df["_sensitive_file"] = np.where(df["event_type"] == "file_access", sensitive_hit, False)

    # Rare process: process name outside the globally-common set for this stream
    process_counts = df.loc[df["event_type"] == "process_execution", "process"].value_counts()
    common_processes = set(process_counts[process_counts > 50].index)
    df["_rare_process"] = (df["event_type"] == "process_execution") & ~df["process"].isin(
        common_processes
    )

    grouped = df.groupby(["host", "minute"])

    def agg_bucket(g: pd.DataFrame) -> dict[str, Any]:
        auth = g[g["event_type"] == "authentication"]
        net = g[g["event_type"] == "network_connection"]
        files = g[g["event_type"] == "file_access"]
        bytes_out = net["bytes_transferred"].fillna(0).sum()
        return {
            "n_events": len(g),
            "n_auth_fail": int((auth["action"] == "login_failure").sum()),
            "n_auth_success": int((auth["action"] == "login_success").sum()),
            "n_unique_users": auth["user"].nunique(),
            "n_unique_src_ips": g["src_ip"].nunique(),
            "n_proc_exec": int((g["event_type"] == "process_execution").sum()),
            "n_rare_process": int(g["_rare_process"].sum()),
            "n_file_ops": len(files),
            "n_sensitive_files": int(g["_sensitive_file"].sum()),
            "n_priv_esc": int((g["event_type"] == "privilege_change").sum()),
            "n_net_conns": len(net),
            "n_external_dst": int(net["_external_dst"].sum()),
            "bytes_out": float(bytes_out),
            "dst_port_entropy": _entropy(net["dst_port"].dropna().astype(str)),
            "mean_severity": float(g["severity"].mean()) if len(g) else 0.0,
            "label_attack": int((g["label"] == "attack").any()),
        }

    rows: list[dict[str, Any]] = []
    index_names: list[tuple[str, pd.Timestamp]] = []
    for key, g in grouped:
        rows.append(agg_bucket(g))
        index_names.append(key)

    features = pd.DataFrame(
        rows, index=pd.MultiIndex.from_tuples(index_names, names=["host", "minute"])
    )
    features = features.sort_index()

    # Rolling context: previous WINDOW_MINUTES minutes per host
    roll_cols = [
        "n_events",
        "n_auth_fail",
        "n_auth_success",
        "n_unique_src_ips",
        "n_proc_exec",
        "n_rare_process",
        "n_file_ops",
        "n_priv_esc",
        "n_net_conns",
        "bytes_out",
    ]
    rolling = (
        features[roll_cols]
        .groupby(level="host", group_keys=False)
        .apply(lambda g: g.shift(1).rolling(WINDOW_MINUTES, min_periods=1).sum())
    )
    rolling.columns = [f"{c}_prev{WINDOW_MINUTES}m" for c in roll_cols]
    features = pd.concat([features.drop(columns=roll_cols), features[roll_cols], rolling], axis=1)

    features = features.fillna(0.0).reset_index()
    return features


FEATURE_COLUMNS = [
    "n_events",
    "n_auth_fail",
    "n_auth_success",
    "n_unique_users",
    "n_unique_src_ips",
    "n_proc_exec",
    "n_rare_process",
    "n_file_ops",
    "n_sensitive_files",
    "n_priv_esc",
    "n_net_conns",
    "n_external_dst",
    "bytes_out",
    "dst_port_entropy",
    "mean_severity",
    "n_events_prev5m",
    "n_auth_fail_prev5m",
    "n_auth_success_prev5m",
    "n_unique_src_ips_prev5m",
    "n_proc_exec_prev5m",
    "n_rare_process_prev5m",
    "n_file_ops_prev5m",
    "n_priv_esc_prev5m",
    "n_net_conns_prev5m",
    "bytes_out_prev5m",
]
