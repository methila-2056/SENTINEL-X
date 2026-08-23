"""Cleaning helpers shared across ingestion pipelines."""

import numpy as np
import pandas as pd


def clean_column_names(df: pd.DataFrame) -> pd.DataFrame:
    """CIC-IDS2017 CSVs contain columns like ' Destination Port' with stray spaces."""
    df.columns = [c.strip() for c in df.columns]
    return df


def replace_numeric_junk(
    df: pd.DataFrame, columns: list[str], clip_max: float = 1e12
) -> pd.DataFrame:
    """Replace inf/NaN with 0 and clip extreme outliers in numeric feature columns."""
    for col in columns:
        if col in df.columns:
            df[col] = pd.to_numeric(df[col], errors="coerce")
            df[col] = (
                df[col]
                .replace([np.inf, -np.inf], np.nan)
                .fillna(0.0)
                .clip(lower=0.0, upper=clip_max)
            )
    return df


def parse_mixed_timestamps(series: pd.Series) -> pd.Series:
    """CIC-IDS2017 timestamps mix d/m/Y formats; dayfirst=True handles both."""
    return pd.to_datetime(series, dayfirst=True, errors="coerce")
