"""Tests for dataset download validation."""

from sentinel_x.data.ingestion.download import PARQUET_MAGIC, _looks_like_parquet


def test_valid_parquet_magic_accepted() -> None:
    head = PARQUET_MAGIC + b"\x00" * 508
    assert _looks_like_parquet(head) is True


def test_html_error_page_rejected() -> None:
    head = b"<html><body><h1>404 Not Found</h1></body></html>" + b"\x00" * 400
    assert _looks_like_parquet(head) is False


def test_html_error_page_without_literal_tag_rejected() -> None:
    # Regression: plain-text/JSON error pages carry no '<html' but are also
    # not parquet; the old `or` logic accepted them as valid downloads.
    head = b'{"error": "rate limited", "detail": "try again later"}' + b"\x00" * 400
    assert _looks_like_parquet(head) is False


def test_empty_head_rejected() -> None:
    assert _looks_like_parquet(b"") is False


def test_binary_garbage_rejected() -> None:
    assert _looks_like_parquet(b"\x25\x50\x44\x46" + b"\x00" * 500) is False  # "%PDF-"
