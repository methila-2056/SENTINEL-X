"""Tests for knowledge-document chunking."""

from sentinel_x.rag.ingestion.chunker import chunk_text


def test_empty_and_whitespace_return_no_chunks() -> None:
    assert chunk_text("") == []
    assert chunk_text("   \n\t  ") == []


def test_short_text_single_chunk() -> None:
    text = "A concise threat description that is long enough to survive the minimum length filter."
    chunks = chunk_text(text, max_chars=900, overlap=150)
    assert len(chunks) == 1
    assert chunks[0] == " ".join(text.split())


def test_paragraph_boundaries_are_respected() -> None:
    para_a = "First paragraph about lateral movement. " * 20
    para_b = "Second paragraph about credential dumping. " * 20
    text = para_a + "\n\n" + para_b

    chunks = chunk_text(text, max_chars=200, overlap=50)

    # Each paragraph fits in one window of 200 chars only if <= 200 chars;
    # these are longer, so each becomes its own sliding-window series.
    joined = "\n".join(chunks)
    assert "Second paragraph" in joined
    # No chunk may straddle the two paragraphs' distinctive phrases.
    for c in chunks:
        assert not ("lateral movement" in c and "credential dumping" in c)


def test_single_long_paragraph_hard_split_with_overlap() -> None:
    para = ("x" * 80 + " ") * 30  # ~2430 chars, no blank lines
    chunks = chunk_text(para.strip(), max_chars=900, overlap=150)

    assert len(chunks) >= 3
    assert all(len(c) <= 900 or len(c) < 60 + len(chunks[-2]) for c in chunks[:-1])
    # Overlap: consecutive windows share content.
    assert chunks[0][150:160] == chunks[1][:10]


def test_internal_whitespace_is_collapsed() -> None:
    text = "token1\ttoken2\n\npara with\nsoft\r\nbreaks that continues long enough here."
    chunks = chunk_text(text, max_chars=900, overlap=150)
    assert len(chunks) == 1
    assert "\n" not in chunks[0]
    assert "\t" not in chunks[0]


def test_min_length_filter_drops_tiny_chunks() -> None:
    text = "Short.\n\nThis paragraph is definitely long enough to be kept as a chunk."
    chunks = chunk_text(text, max_chars=900, overlap=150)
    assert all(len(c) >= 40 for c in chunks)
