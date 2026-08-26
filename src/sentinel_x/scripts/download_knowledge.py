"""Download threat-intelligence knowledge sources into data/raw/.

Sources:
- MITRE ATT&CK Enterprise STIX bundle (techniques, tactics, mitigations)
- SigmaHQ rules repository (detection rules)

Usage:
    sentinelx-download-knowledge [--skip-mitre] [--skip-sigma]
"""

import argparse
import shutil
import zipfile
from pathlib import Path

import httpx
import structlog

from sentinel_x.common.logging import configure_logging

logger = structlog.get_logger(__name__)

MITRE_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
    "master/enterprise-attack/enterprise-attack.json"
)
SIGMA_ZIP_URL = "https://codeload.github.com/SigmaHQ/sigma/zip/refs/heads/master"


def download_mitre(raw_dir: Path) -> Path | None:
    dest = raw_dir / "mitre" / "enterprise-attack.json"
    if dest.exists() and dest.stat().st_size > 10_000_000:
        logger.info("mitre_already_present", path=str(dest))
        return dest
    dest.parent.mkdir(parents=True, exist_ok=True)
    partial = dest.with_suffix(".json.part")
    try:
        with httpx.stream("GET", MITRE_URL, timeout=None, follow_redirects=True) as resp:
            resp.raise_for_status()
            with open(partial, "wb") as fh:
                for chunk in resp.iter_bytes(1024 * 1024):
                    fh.write(chunk)
        partial.rename(dest)
        logger.info("mitre_downloaded", bytes=dest.stat().st_size)
        return dest
    except Exception as exc:  # noqa: BLE001
        logger.error("mitre_download_failed", error=str(exc))
        partial.unlink(missing_ok=True)
        return None


def download_sigma(raw_dir: Path) -> Path | None:
    final_rules = raw_dir / "sigma" / "rules"
    if final_rules.exists():
        logger.info("sigma_already_present", path=str(final_rules))
        return final_rules
    zip_path = raw_dir / "sigma-master.zip"
    zip_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with httpx.stream("GET", SIGMA_ZIP_URL, timeout=None, follow_redirects=True) as resp:
            resp.raise_for_status()
            with open(zip_path, "wb") as fh:
                for chunk in resp.iter_bytes(1024 * 1024):
                    fh.write(chunk)
        extract_dir = raw_dir / "sigma_extract"
        with zipfile.ZipFile(zip_path) as zf:
            zf.extractall(extract_dir)
        extracted = next(extract_dir.glob("sigma-*/rules"))
        shutil.move(str(extracted), str(final_rules))
        shutil.rmtree(extract_dir, ignore_errors=True)
        zip_path.unlink(missing_ok=True)
        n_rules = len(list(final_rules.rglob("*.yml")))
        logger.info("sigma_downloaded", rules=n_rules)
        return final_rules
    except Exception as exc:  # noqa: BLE001
        logger.error("sigma_download_failed", error=str(exc))
        return None


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--skip-mitre", action="store_true")
    parser.add_argument("--skip-sigma", action="store_true")
    args = parser.parse_args()
    configure_logging()

    raw_dir = Path("data/raw")
    if not args.skip_mitre:
        download_mitre(raw_dir)
    if not args.skip_sigma:
        download_sigma(raw_dir)
    return 0
