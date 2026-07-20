"""Dependency Scanner Module

Scans project dependencies for known vulnerabilities.
Primary source: OSV API (https://api.osv.dev) — real-time vulnerability database.
Fallback: local hardcoded vulnerable package dictionary.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Optional

import httpx
from core.retry import retry
from rich.console import Console

console = Console()

# Known vulnerable package versions (simplified - in production use OSV/NVD API)
OSV_API_URL = "https://api.osv.dev/v1/query"
OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_TIMEOUT = 10


# ─── OSV API Client ─────────────────────────────────────────────


@retry(max_retries=2, exceptions=(httpx.RequestError, httpx.TimeoutException))
def _query_osv(package_name: str, version: str, ecosystem: str = "PyPI") -> list[dict]:
    """Query OSV API for vulnerabilities of a specific package version."""
    try:
        client = httpx.Client(timeout=OSV_TIMEOUT)
        resp = client.post(
            OSV_API_URL,
            json={
                "version": version,
                "package": {"name": package_name, "ecosystem": ecosystem},
            },
        )
        resp.raise_for_status()
        data = resp.json()
        vulns = data.get("vulnerabilities", [])
        results = []
        for v in vulns:
            v_id = v.get("id", "unknown")
            aliases = v.get("aliases", [])
            summary = v.get("summary", v.get("details", "")[:200])
            severity = "unknown"
            # Extract severity from database_specific or severity field
            for sev in v.get("severity", []):
                if sev.get("type") == "CVSS_V3":
                    score_str = sev.get("score", "")
                    # Parse CVSS vector for severity
                    if "CRITICAL" in score_str.upper():
                        severity = "critical"
                    elif "HIGH" in score_str.upper():
                        severity = "high"
                    elif "MEDIUM" in score_str.upper():
                        severity = "medium"
                    elif "LOW" in score_str.upper():
                        severity = "low"
            # Extract CWE
            cwe = ""
            for ref in v.get("references", []):
                url = ref.get("url", "")
                if "cwe.mitre.org" in url:
                    cwe_match = re.search(r'CWE-\d+', url)
                    if cwe_match:
                        cwe = cwe_match.group()
                        break
            # If no severity, try to infer from database_specific
            if severity == "unknown":
                db_sev = v.get("database_specific", {}).get("severity", "")
                if db_sev:
                    severity = db_sev.lower()
            results.append({
                "id": v_id,
                "aliases": aliases,
                "summary": summary[:200],
                "severity": severity,
                "cwe": cwe,
            })
        return results
    except Exception:
        return []


# Known vulnerable package versions (local fallback when OSV is unavailable)
VULNERABLE_PACKAGES = {
    # Python
    "django": {
        "vulnerable_below": "4.2.0",
        "cwe": "CWE-89",
        "description": "Old Django versions have SQL injection vulnerabilities",
    },
    "flask": {
        "vulnerable_below": "2.3.0",
        "cwe": "CWE-79",
        "description": "Old Flask versions have XSS vulnerabilities",
    },
    "requests": {
        "vulnerable_below": "2.31.0",
        "cwe": "CWE-295",
        "description": "Old requests versions have certificate verification issues",
    },
    "pyyaml": {
        "vulnerable_below": "6.0",
        "cwe": "CWE-502",
        "description": "Old PyYAML versions allow arbitrary code execution via yaml.load()",
    },
    "pillow": {
        "vulnerable_below": "10.0.0",
        "cwe": "CWE-120",
        "description": "Old Pillow versions have buffer overflow vulnerabilities",
    },
    "cryptography": {
        "vulnerable_below": "41.0.0",
        "cwe": "CWE-327",
        "description": "Old cryptography versions have weak algorithm support",
    },
    # JavaScript
    "lodash": {
        "vulnerable_below": "4.17.21",
        "cwe": "CWE-1321",
        "description": "Old lodash versions have prototype pollution vulnerability",
    },
    "express": {
        "vulnerable_below": "4.18.0",
        "cwe": "CWE-1321",
        "description": "Old Express versions have open redirect vulnerabilities",
    },
    "axios": {
        "vulnerable_below": "1.6.0",
        "cwe": "CWE-918",
        "description": "Old Axios versions have SSRF vulnerability",
    },
}


def _parse_version(version_str: str) -> tuple[int, ...]:
    """Parse version string to tuple for comparison."""
    # Remove leading ^, ~, >=, <=, ==, !=, etc.
    cleaned = re.sub(r'^[><=!~^]+', '', version_str.strip())
    parts = []
    for p in cleaned.split('.'):
        try:
            parts.append(int(p))
        except ValueError:
            break
    return tuple(parts) if parts else (0,)


def _version_below(current: str, threshold: str) -> bool:
    """Check if current version is below threshold."""
    return _parse_version(current) < _parse_version(threshold)


def scan_requirements_txt(file_path: Path) -> list[dict]:
    """Scan Python requirements.txt for vulnerable packages.

    Uses OSV API as primary source, falls back to local dictionary.
    """
    findings = []
    try:
        content = file_path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return findings

    for line in content.split("\n"):
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue

        # Parse package==version or package>=version
        match = re.match(r'^([a-zA-Z0-9_-]+)\s*[><=!~]+\s*([0-9][0-9.]*)', line)
        if match:
            pkg_name = match.group(1).lower()
            version = match.group(2)

            # Try OSV API first
            osv_vulns = _query_osv(pkg_name, version)
            if osv_vulns:
                for v in osv_vulns:
                    findings.append({
                        "package": pkg_name,
                        "version": version,
                        "cwe": v.get("cwe", "CWE-000"),
                        "description": v.get("summary", "Vulnerability found via OSV"),
                        "fix": f"Upgrade {pkg_name} — see {v.get('id', 'OSV')} for details",
                        "source": "osv",
                        "osv_id": v.get("id", ""),
                    })
            else:
                # Fallback to local dictionary
                if pkg_name in VULNERABLE_PACKAGES:
                    vuln = VULNERABLE_PACKAGES[pkg_name]
                    if _version_below(version, vuln["vulnerable_below"]):
                        findings.append({
                            "package": pkg_name,
                            "version": version,
                            "cwe": vuln["cwe"],
                            "description": vuln["description"],
                            "fix": f"Upgrade {pkg_name} to >= {vuln['vulnerable_below']}",
                            "source": "local",
                        })

    return findings


def scan_package_json(file_path: Path) -> list[dict]:
    """Scan Node.js package.json for vulnerable packages."""
    findings = []
    try:
        content = file_path.read_text(encoding="utf-8", errors="replace")
        data = json.loads(content)
    except Exception:
        return findings

    deps = {}
    deps.update(data.get("dependencies", {}))
    deps.update(data.get("devDependencies", {}))

    for pkg_name, version in deps.items():
        pkg_lower = pkg_name.lower()
        if pkg_lower in VULNERABLE_PACKAGES:
            vuln = VULNERABLE_PACKAGES[pkg_lower]
            # Extract version number from semver range
            clean_version = re.sub(r'^[><=!~^]+', '', version.strip())
            if clean_version and _version_below(clean_version, vuln["vulnerable_below"]):
                findings.append({
                    "package": pkg_name,
                    "version": version,
                    "cwe": vuln["cwe"],
                    "description": vuln["description"],
                    "fix": f"Upgrade {pkg_name} to >= {vuln['vulnerable_below']}",
                })

    return findings


def scan_project_dependencies(project_path: Path) -> list[dict]:
    """Scan a project directory for dependency vulnerabilities."""
    all_findings = []

    # Check requirements.txt
    req_file = project_path / "requirements.txt"
    if req_file.exists():
        findings = scan_requirements_txt(req_file)
        for f in findings:
            f["file"] = str(req_file)
        all_findings.extend(findings)

    # Check pyproject.toml (simplified)
    pyproject = project_path / "pyproject.toml"
    if pyproject.exists():
        try:
            content = pyproject.read_text()
            # Extract dependencies section
            deps_match = re.search(r'dependencies\s*=\s*\[(.*?)\]', content, re.DOTALL)
            if deps_match:
                for line in deps_match.group(1).split("\n"):
                    match = re.match(r'^\s*"([a-zA-Z0-9_-]+)[><=!~]*([0-9][0-9.]*)', line)
                    if match:
                        pkg_name = match.group(1).lower()
                        version = match.group(2)
                        if pkg_name in VULNERABLE_PACKAGES:
                            vuln = VULNERABLE_PACKAGES[pkg_name]
                            if _version_below(version, vuln["vulnerable_below"]):
                                all_findings.append({
                                    "package": pkg_name,
                                    "version": version,
                                    "cwe": vuln["cwe"],
                                    "description": vuln["description"],
                                    "fix": f"Upgrade {pkg_name} to >= {vuln['vulnerable_below']}",
                                    "file": str(pyproject),
                                })
        except Exception:
            pass

    # Check package.json
    pkg_json = project_path / "package.json"
    if pkg_json.exists():
        findings = scan_package_json(pkg_json)
        for f in findings:
            f["file"] = str(pkg_json)
        all_findings.extend(findings)

    return all_findings
