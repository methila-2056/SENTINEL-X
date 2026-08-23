"""CIC-IDS2017 normalizer.

Produces two artifacts from raw TrafficLabelling CSVs:

1. events.parquet    - canonical SecurityEvent rows (network-flow view) for the
                       correlation engine, graph and retrieval layers.
2. features.parquet  - cleaned numeric flow features + label for supervised ML.
"""

from pathlib import Path

import pandas as pd
import structlog

from sentinel_x.data.preprocessing.cleaning import (
    clean_column_names,
    replace_numeric_junk,
)

logger = structlog.get_logger(__name__)

# Flow feature columns kept as ML features (canonical CIC-IDS2017 names).
FLOW_FEATURES = [
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Total Length of Fwd Packets",
    "Total Length of Bwd Packets",
    "Fwd Packet Length Max",
    "Fwd Packet Length Mean",
    "Bwd Packet Length Mean",
    "Flow Bytes/s",
    "Flow Packets/s",
    "Flow IAT Mean",
    "Flow IAT Std",
    "Min Packet Length",
    "Max Packet Length",
    "Packet Length Mean",
    "Packet Length Variance",
    "FIN Flag Count",
    "SYN Flag Count",
    "RST Flag Count",
    "PSH Flag Count",
    "ACK Flag Count",
    "Average Packet Size",
    "Subflow Fwd Bytes",
    "Init_Win_bytes_forward",
    "Init_Win_bytes_backward",
    "Active Mean",
    "Idle Mean",
]

LABEL_MAP = {
    "BENIGN": ("benign", None),
    "DDoS": ("attack", "ddos"),
    "DoS Hulk": ("attack", "dos"),
    "DoS GoldenEye": ("attack", "dos"),
    "DoS Slowloris": ("attack", "dos"),
    "DoS Slowhttptest": ("attack", "dos"),
    "PortScan": ("attack", "port_scan"),
    "Bot": ("attack", "botnet"),
    "Infiltration": ("attack", "infiltration"),
    "Heartbleed": ("attack", "exploitation"),
    "FTP-Patator": ("attack", "brute_force"),
    "SSH-Patator": ("attack", "brute_force"),
    "Web Attack - Brute Force": ("attack", "web_attack"),
    "Web Attack - XSS": ("attack", "web_attack"),
    "Web Attack - Sql Injection": ("attack", "web_attack"),
}


def load_raw_files(raw_dir: Path) -> pd.DataFrame:
    """Load and concatenate all raw parquet files with cleaned columns."""
    files = sorted(raw_dir.glob("*.parquet"))
    if not files:
        raise FileNotFoundError(f"No parquet files found in {raw_dir}")
    frames: list[pd.DataFrame] = []
    for path in files:
        logger.info("loading_raw", file=path.name)
        df = pd.read_parquet(path)
        df = clean_column_names(df)
        df["__source_file"] = path.stem
        frames.append(df)
    return pd.concat(frames, ignore_index=True)


def normalize(raw_dir: Path, out_dir: Path) -> tuple[Path, Path]:
    """Normalize raw CSVs into canonical events + ML feature table."""
    out_dir.mkdir(parents=True, exist_ok=True)
    df = load_raw_files(raw_dir)

    # --- Label normalization -------------------------------------------------
    unknown_labels = set(df["Label"].unique()) - set(LABEL_MAP)
    if unknown_labels:
        logger.warning("unknown_labels_mapped_to_attack", labels=sorted(unknown_labels))
        for lbl in unknown_labels:
            LABEL_MAP[lbl] = ("attack", "other")
    label_norm = df["Label"].map(lambda x: LABEL_MAP.get(x, ("benign", None)))
    df["label"] = [pair[0] for pair in label_norm]
    df["attack_category"] = [pair[1] for pair in label_norm]

    # --- Timestamps ----------------------------------------------------------
    if "Timestamp" in df.columns:
        ts = pd.to_datetime(df["Timestamp"], errors="coerce", utc=True, dayfirst=False)
        # Some rows may still be strings with d/m/Y ordering; fall back to dayfirst
        if ts.isna().mean() > 0.5:
            ts = pd.to_datetime(df["Timestamp"], errors="coerce", utc=True, dayfirst=True)
    else:
        raise ValueError("TrafficLabelling files must contain a Timestamp column")
    valid_ts = ts.notna()

    # --- Canonical event table -----------------------------------------------
    events = pd.DataFrame(
        {
            "event_id": ["cic-" + str(i) for i in range(len(df))],
            "timestamp": ts,
            "source": "flow_sensor",
            "event_type": "network_connection",
            "action": "connect",
            "user": None,
            "host": df.get("Destination IP"),
            "process": None,
            "src_ip": df.get("Source IP"),
            "dst_ip": df.get("Destination IP"),
            "dst_port": pd.to_numeric(df.get("Destination Port"), errors="coerce"),
            "file_path": None,
            "bytes_transferred": pd.to_numeric(
                df.get("Total Length of Fwd Packets"), errors="coerce"
            ),
            "severity": 1,
            "label": df["label"],
            "attack_category": df["attack_category"],
            "technique_id": None,
            "incident_id": None,
            "metadata_source_file": df["__source_file"],
            "protocol": df.get("Protocol"),
        }
    )
    events = events[valid_ts].reset_index(drop=True)
    events_path = out_dir / "events.parquet"
    events.to_parquet(events_path, index=False)
    logger.info("events_written", path=str(events_path), rows=len(events))

    # --- ML feature table ----------------------------------------------------
    missing = [c for c in FLOW_FEATURES if c not in df.columns]
    if missing:
        logger.warning("missing_flow_features", missing=missing)
    features = df[
        [c for c in FLOW_FEATURES if c in df.columns] + ["label", "attack_category"]
    ].copy()
    numeric_cols = [c for c in FLOW_FEATURES if c in features.columns]
    features = replace_numeric_junk(features, numeric_cols)
    features = features[valid_ts.reindex(features.index, fill_value=True)].reset_index(drop=True)
    features_path = out_dir / "features.parquet"
    features.to_parquet(features_path, index=False)
    logger.info("features_written", path=str(features_path), rows=len(features))

    report = (
        features.groupby(["label", "attack_category"], dropna=False)
        .size()
        .rename("rows")
        .reset_index()
    )
    report.to_csv(out_dir / "label_report.csv", index=False)
    return events_path, features_path
