"""Resumable downloader for CIC-IDS2017 dataset files.

Downloads the TrafficLabelling variant which includes Source/Destination IPs
and timestamps, enabling temporal windows and entity-graph construction.
"""

from pathlib import Path

import httpx
import structlog

logger = structlog.get_logger(__name__)

BASE_URL_CANDIDATES = [
    "https://cicresearch.ca/CICDataset/CIC-IDS-2017/Dataset/TrafficLabelling/",
    "http://cicresearch.ca/CICDataset/CIC-IDS-2017/Dataset/TrafficLabelling/",
]

# Ordered smallest-first so early files validate connectivity quickly.
FILES = [
    "Monday-WorkingHours.pcap_ISCX.csv",
    "Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv",
    "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv",
    "Tuesday-WorkingHours.pcap_ISCX.csv",
    "Wednesday-workingHours.pcap_ISCX.csv",
    "Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv",
    "Friday-WorkingHours-Morning.pcap_ISCX.csv",
    "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv",
]

CHUNK_SIZE = 1024 * 1024


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
                mode = "ab" if (resp.status_code == 206 and existing_size) else "wb"
                with open(partial, mode) as fh:
                    async for chunk in resp.aiter_bytes(CHUNK_SIZE):
                        fh.write(chunk)
            final_size = partial.stat().st_size
            if final_size == 0:
                logger.warning("download_empty", url=url)
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
            result = await download_file(client, BASE_URL_CANDIDATES, filename, raw_dir)
            if result is not None:
                downloaded.append(filename)
            else:
                logger.error("download_exhausted_mirrors", file=filename)
    return downloaded
