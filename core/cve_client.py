"""CodeRisk Agent - CVE/NVD Client

Queries NVD (National Vulnerability Database) for CVE information.
Used by DeepVerifier for knowledge-base cross-validation.
"""

from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Optional

import httpx
from rich.console import Console

console = Console()

NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
REQUEST_TIMEOUT = 15
RATE_LIMIT_DELAY = 1.0  # NVD rate limit: 5 requests/30s without API key
CACHE_DIR = Path(os.getenv("CODERISK_CACHE_DIR", str(Path.home() / ".coderisk" / "cache")))
CACHE_FILE = CACHE_DIR / "cve_cache.json"
CACHE_TTL_SECONDS = 86400  # 24 hours


class CVEClient:
    """Query NVD for CVE information by CWE ID or keyword.

    Features:
    - In-memory cache for fast access
    - Persistent disk cache (survives restarts)
    - TTL-based expiry (24h default)
    """

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key
        self._client = httpx.Client(timeout=REQUEST_TIMEOUT)
        self._cache: dict[str, dict] = {}  # key -> {data, timestamp}
        self._last_request_time = 0.0
        self._dirty = False
        self._load_disk_cache()

    def query_by_cwe(
        self,
        cwe_id: str,
        max_results: int = 5,
    ) -> list[dict]:
        """Query CVEs associated with a CWE ID.

        Args:
            cwe_id: CWE identifier, e.g. "CWE-120"
            max_results: Maximum number of CVEs to return

        Returns:
            List of CVE summaries with id, description, severity, references
        """
        # Check cache (memory + disk)
        cache_key = f"{cwe_id}:{max_results}"
        cached = self._get_cached(cache_key)
        if cached is not None:
            return cached

        # Sanitize CWE ID: extract just "CWE-xxx" from strings like "CWE-676: Use of..."
        import re
        cwe_match = re.match(r'(CWE-\d+)', cwe_id)
        if cwe_match:
            cwe_id = cwe_match.group(1)
        else:
            console.print(f"[dim]Invalid CWE ID format: {cwe_id}[/]")
            return []

        # Rate limiting
        self._rate_limit()

        params = {
            "cweId": cwe_id,
            "resultsPerPage": max_results,
        }
        if self.api_key:
            params["apiKey"] = self.api_key

        try:
            resp = self._client.get(NVD_API_BASE, params=params)
            resp.raise_for_status()
            data = resp.json()
        except Exception as e:
            console.print(f"[dim]CVE query failed for {cwe_id}: {e}[/]")
            return []

        vulnerabilities = data.get("vulnerabilities", [])
        results = []

        for vuln in vulnerabilities:
            cve = vuln.get("cve", {})
            cve_id = cve.get("id", "unknown")

            # Extract description
            descriptions = cve.get("descriptions", [])
            desc_en = ""
            for d in descriptions:
                if d.get("lang") == "en":
                    desc_en = d.get("value", "")
                    break

            # Extract severity from CVSS
            metrics = cve.get("metrics", {})
            severity = "unknown"
            cvss_score = 0.0

            # Try CVSS v3.1 first, then v3.0, then v2.0
            for version_key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                version_metrics = metrics.get(version_key, [])
                if version_metrics:
                    cvss_data = version_metrics[0].get("cvssData", {})
                    cvss_score = cvss_data.get("baseScore", 0.0)
                    severity = cvss_data.get("baseSeverity", "unknown").lower()
                    break

            # Extract references
            references = []
            for ref in cve.get("references", [])[:3]:
                references.append(ref.get("url", ""))

            results.append({
                "cve_id": cve_id,
                "description": desc_en[:300],
                "severity": severity,
                "cvss_score": cvss_score,
                "references": references,
            })

        # Cache results (memory + mark for disk flush)
        self._set_cache(cache_key, results)
        return results

    def has_known_exploits(self, cwe_id: str) -> bool:
        """Check if a CWE has known exploitable CVEs (quick check)."""
        results = self.query_by_cwe(cwe_id, max_results=3)
        # If any CVE has high/critical severity, consider it exploitable
        return any(
            r["severity"] in ("high", "critical") and r["cvss_score"] >= 7.0
            for r in results
        )

    def get_cve_summary(self, cwe_id: str) -> str:
        """Get a brief summary of CVEs for a CWE (for report inclusion)."""
        results = self.query_by_cwe(cwe_id, max_results=3)
        if not results:
            return f"No CVE data found for {cwe_id}"

        summaries = []
        for r in results:
            summaries.append(
                f"{r['cve_id']} ({r['severity']}, CVSS {r['cvss_score']}): "
                f"{r['description'][:100]}..."
            )
        return " | ".join(summaries)

    def _get_cached(self, key: str) -> Optional[list[dict]]:
        """Get from cache if not expired."""
        entry = self._cache.get(key)
        if entry is None:
            return None
        if time.time() - entry["timestamp"] > CACHE_TTL_SECONDS:
            del self._cache[key]
            self._dirty = True
            return None
        return entry["data"]

    def _set_cache(self, key: str, data: list[dict]):
        """Set cache entry and flush to disk."""
        self._cache[key] = {"data": data, "timestamp": time.time()}
        self._dirty = True
        self._flush_disk_cache()

    def _load_disk_cache(self):
        """Load cache from disk."""
        try:
            if CACHE_FILE.exists():
                raw = json.loads(CACHE_FILE.read_text(encoding="utf-8"))
                # Filter expired entries
                now = time.time()
                self._cache = {
                    k: v for k, v in raw.items()
                    if now - v.get("timestamp", 0) < CACHE_TTL_SECONDS
                }
                console.print(f"[dim]CVE cache loaded: {len(self._cache)} entries[/]")
        except Exception as e:
            console.print(f"[dim]CVE cache load failed (will rebuild): {e}[/]")
            self._cache = {}

    def _flush_disk_cache(self):
        """Persist cache to disk."""
        if not self._dirty:
            return
        try:
            CACHE_DIR.mkdir(parents=True, exist_ok=True)
            CACHE_FILE.write_text(
                json.dumps(self._cache, ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
            self._dirty = False
        except Exception as e:
            console.print(f"[dim]CVE cache flush failed: {e}[/]")

    def _rate_limit(self):
        """Respect NVD rate limits."""
        elapsed = time.monotonic() - self._last_request_time
        if elapsed < RATE_LIMIT_DELAY:
            time.sleep(RATE_LIMIT_DELAY - elapsed)
        self._last_request_time = time.monotonic()

    def close(self):
        self._flush_disk_cache()
        self._client.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()
