"""Tests for CIC-IDS2017 label normalization."""

import pandas as pd

from sentinel_x.data.ingestion.cic_ids2017 import LABEL_MAP, build_label_map


def test_known_labels_resolved() -> None:
    mapping = build_label_map({"BENIGN", "DDoS", "PortScan"})
    assert mapping["BENIGN"] == ("benign", None)
    assert mapping["DDoS"] == ("attack", "ddos")
    assert mapping["PortScan"] == ("attack", "port_scan")


def test_unknown_labels_mapped_to_attack_without_mutating_global() -> None:
    snapshot = dict(LABEL_MAP)
    mapping = build_label_map({"BENIGN", "Totally-New-Label"})

    assert mapping["Totally-New-Label"] == ("attack", "other")
    assert mapping["BENIGN"] == ("benign", None)
    # The module-level map must remain untouched across calls.
    assert snapshot == LABEL_MAP
    assert "Totally-New-Label" not in LABEL_MAP


def test_repeated_calls_are_independent() -> None:
    first = build_label_map({"Mystery-A"})
    second = build_label_map({"Mystery-B"})
    assert "Mystery-B" not in first
    assert "Mystery-A" not in second


def test_accepts_pandas_index() -> None:
    labels = pd.Index(["BENIGN", "Heartbleed"])
    mapping = build_label_map(labels)
    assert mapping["Heartbleed"] == ("attack", "exploitation")
