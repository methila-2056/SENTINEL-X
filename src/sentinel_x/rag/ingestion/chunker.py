"""Text chunking for knowledge documents."""

import re


def chunk_text(
    text: str,
    max_chars: int = 900,
    overlap: int = 150,
) -> list[str]:
    """Paragraph-aware sliding-window chunking.

    Splits on blank lines first; long paragraphs are hard-split with overlap.
    """
    text = text.strip()
    if not text:
        return []
    # Split on blank lines BEFORE collapsing whitespace, otherwise paragraph
    # boundaries are destroyed and every document degrades to one hard-split window.
    paragraphs = [re.sub(r"\s+", " ", p).strip() for p in re.split(r"\n\s*\n", text) if p.strip()]

    chunks: list[str] = []
    current = ""
    for para in paragraphs:
        if len(para) > max_chars:
            # Flush current buffer, then slide over the long paragraph
            if current:
                chunks.append(current.strip())
                current = ""
            step = max(max_chars - overlap, 1)
            for start in range(0, len(para), step):
                piece = para[start : start + max_chars]
                if len(piece) < 60 and chunks:
                    chunks[-1] += " " + piece
                else:
                    chunks.append(piece)
            current = ""
            continue
        if len(current) + len(para) + 1 <= max_chars:
            current = f"{current} {para}".strip()
        else:
            if current:
                chunks.append(current.strip())
            current = para
    if current.strip():
        chunks.append(current.strip())
    return [c for c in chunks if len(c) >= 40]
