"""Download threat intelligence feeds and populate the IOC database.

Fetches indicators from public threat-intel sources and upserts them
into the Aegis ``ioc_indicators`` table.

Run: ``python scripts/download_feeds.py [--db path/to/aegis.db]``
"""

from __future__ import annotations

import argparse
import csv
import io
import json
import logging
import sys
import urllib.request
from pathlib import Path

# Ensure the src directory is importable
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from aegis.core.database import AegisDatabase  # noqa: E402

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Feed definitions
# ---------------------------------------------------------------------------

ABUSE_IPDB_URL = (
    "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.json"
)
PHISHTANK_URL = (
    "http://data.phishtank.com/data/online-valid.csv"
)

DEFAULT_DB = Path("data") / "aegis.db"


def fetch_json(url: str) -> list[dict]:
    """Download JSON from *url* and return parsed data."""
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Aegis/1.0"})
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except Exception:
        logger.exception("Failed to fetch %s", url)
        return []


def fetch_csv_rows(url: str, max_rows: int = 5000) -> list[dict]:
    """Download CSV from *url* and return list of row dicts."""
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Aegis/1.0"})
        with urllib.request.urlopen(req, timeout=60) as resp:
            text = resp.read().decode("utf-8", errors="replace")
        reader = csv.DictReader(io.StringIO(text))
        rows = []
        for i, row in enumerate(reader):
            if i >= max_rows:
                break
            rows.append(row)
        return rows
    except Exception:
        logger.exception("Failed to fetch %s", url)
        return []


def ingest_abuse_ipdb(db: AegisDatabase) -> int:
    """Ingest Feodo Tracker IP blocklist."""
    data = fetch_json(ABUSE_IPDB_URL)
    count = 0
    for entry in data:
        ip = entry.get("ip_address") or entry.get("ip")
        if not ip:
            continue
        db.upsert_ioc(
            ioc_type="ip",
            value=ip,
            source="feodotracker",
            severity="high",
            metadata={"status": entry.get("status", "")},
        )
        count += 1
    return count


def ingest_phishtank(db: AegisDatabase) -> int:
    """Ingest PhishTank verified phishing URLs."""
    rows = fetch_csv_rows(PHISHTANK_URL, max_rows=5000)
    count = 0
    for row in rows:
        url = row.get("url", "")
        if not url:
            continue
        db.upsert_ioc(
            ioc_type="url",
            value=url[:500],
            source="phishtank",
            severity="high",
            metadata={"target": row.get("target", "")},
        )
        count += 1
    return count


def main() -> None:
    """Download feeds and populate the database."""
    parser = argparse.ArgumentParser(
        description="Download threat intel feeds into Aegis DB",
    )
    parser.add_argument(
        "--db", type=str, default=str(DEFAULT_DB),
        help="Path to Aegis SQLite database",
    )
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO)
    db = AegisDatabase(args.db)

    print("Fetching Feodo Tracker blocklist...")
    n1 = ingest_abuse_ipdb(db)
    print(f"  Ingested {n1} IP indicators")

    print("Fetching PhishTank verified URLs...")
    n2 = ingest_phishtank(db)
    print(f"  Ingested {n2} URL indicators")

    total = db.ioc_count()
    print(f"Total IOC indicators in database: {total}")
    db.close()


if __name__ == "__main__":
    main()
