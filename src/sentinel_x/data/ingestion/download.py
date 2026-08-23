"""Resumable downloader for CIC-IDS2017 dataset files.

Primary source: HuggingFace mirror `bvsam/cic-ids-2017` which provides the
TrafficLabelling CSVs converted to Parquet (Source/Destination IPs retained,
timestamps normalized to UTC). This mirror serves plain HTTP files reliably,
unlike cicresearch.ca which blocks non-browser clients behind a JS challenge.
"""

import asyncio
from pathlib import Path

import httpx
import structlog

logger = structlog.get_logger(__name__)

BASE_URLS = [
    "https://huggingface.co/datasets/bvsam/cic-ids-2017/resolve/main/traffic_labels/",
]

FILES = [
    "Monday-WorkingHours.pcap_ISCX.csv.parquet",
    "Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv.parquet",
    "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv.parquet",
    "Tuesday-WorkingHours.pcap_ISCX.csv.parquet",
    "Wednesday-workingHours.pcap_ISCX.csv.parquet",
    "Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv.parquet",
    "Friday-WorkingHours-Morning.pcap_ISCX.csv.parquet",
    "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv.parquet",
]

CHUNK_SIZE = 1024 * 1024
PARQUET_MAGIC = b"PAR1"


def _looks_like_parquet(head: bytes) -> bool:
    return head[:4] == PARQUET_MAGIC or b"<html" not in head[:512].lower()


async def download_file(
    client: httpx.AsyncClient,
    base_urls: list[str],
    filename: str,
    dest_dir: Path,
) -> Path | None:
    """Download one file with resume support across candidate mirrors."""
    dest = dest_dir / filename
    partial = dest.with_suffix(dest.suffix + ".part")
    existing_size = partial.stat().st_size if partial.exists() else 0

    for base in base_urls:
        url = base + filename
        try:
            headers = {"Range": f"bytes={existing_size}-"} if existing_size else {}
            async with client.stream("GET", url, headers=headers, timeout=None) as resp:
                if resp.status_code not in (200, 206):
                    logger.warning("download_unavailable", url=url, status=resp.status_code)
                    continue
                resumed = resp.status_code == 206 and existing_size > 0
                mode = "ab" if resumed else "wb"
                first_chunk = True
                valid = True
                with open(partial, mode) as fh:
                    async for chunk in resp.aiter_bytes(CHUNK_SIZE):
                        if first_chunk:
                            probe = chunk[:512]
                            # Fresh downloads must look like parquet, never HTML
                            if not resumed and not _looks_like_parquet(probe):
                                logger.warning("download_invalid_content", url=url)
                                valid = False
                                break
                            first_chunk = False
                        fh.write(chunk)
                if not valid:
                    partial.unlink(missing_ok=True)
                    continue
            final_size = partial.stat().st_size
            if final_size < 1024:
                logger.warning("download_too_small", url=url, bytes=final_size)
                partial.unlink(missing_ok=True)
                continue
            partial.rename(dest)
            logger.info("download_complete", file=filename, bytes=final_size)
            return dest
        except Exception as exc:  # noqa: BLE001 - mirror fallback requires broad catch
            logger.warning("download_failed", url=url, error=str(exc))
            continue
    return None


async def download_dataset(raw_dir: Path, only: list[str] | None = None) -> list[str]:
    """Download requested files (default: all). Returns successfully downloaded names."""
    raw_dir.mkdir(parents=True, exist_ok=True)
    wanted = [f for f in FILES if only is None or f in only]
    downloaded: list[str] = []
    async with httpx.AsyncClient(follow_redirects=True) as client:
        for filename in wanted:
            if (raw_dir / filename).exists():
                downloaded.append(filename)
                logger.info("already_present", file=filename)
                continue
            result = await download_file(client, BASE_URLS, filename, raw_dir)
            if result is not None:
                downloaded.append(filename)
            else:
                logger.error("download_exhausted_mirrors", file=filename)
    return downloaded
