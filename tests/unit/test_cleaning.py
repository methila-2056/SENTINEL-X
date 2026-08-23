"""Unit tests for cleaning utilities."""

import numpy as np
import pandas as pd

from sentinel_x.data.preprocessing.cleaning import (
    clean_column_names,
    parse_mixed_timestamps,
    replace_numeric_junk,
)


def test_clean_column_names_strips_spaces() -> None:
    df = pd.DataFrame(columns=[" Destination Port", "Flow Duration", "Label"])
    cleaned = clean_column_names(df)
    assert list(cleaned.columns) == ["Destination Port", "Flow Duration", "Label"]


def test_replace_numeric_junk_handles_inf_and_nan() -> None:
    df = pd.DataFrame({"Flow Bytes/s": [1.0, np.inf, -np.inf, np.nan, 5e13]})
    out = replace_numeric_junk(df, ["Flow Bytes/s"], clip_max=1e12)
    assert out["Flow Bytes/s"].iloc[0] == 1.0
    assert out["Flow Bytes/s"].iloc[1] == 0.0
    assert out["Flow Bytes/s"].iloc[2] == 0.0
    assert out["Flow Bytes/s"].iloc[3] == 0.0
    assert out["Flow Bytes/s"].iloc[4] == 1e12


def test_parse_mixed_timestamps_dayfirst() -> None:
    series = pd.Series(["03/07/2017 08:56:10", "15/07/2017 14:20:00"])
    parsed = parse_mixed_timestamps(series)
    assert parsed.iloc[0].day == 3 and parsed.iloc[0].month == 7
    assert parsed.iloc[1].day == 15


def test_parse_mixed_timestamps_bad_values_become_nat() -> None:
    parsed = parse_mixed_timestamps(pd.Series(["not-a-date"]))
    assert parsed.isna().all()
