"""Tests for CVE Client - Cache persistence, TTL, rate limiting"""

import json
import sys
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from core.cve_client import CVEClient, CACHE_TTL_SECONDS


class TestCVECache:
    def test_memory_cache_hit(self):
        """In-memory cache should return immediately."""
        client = CVEClient.__new__(CVEClient)
        client._cache = {}
        client._dirty = False
        client._client = MagicMock()
        client.api_key = None
        client._last_request_time = 0.0

        # Pre-populate cache
        test_data = [{"cve_id": "CVE-2024-0001", "severity": "high"}]
        client._cache["CWE-120:5"] = {"data": test_data, "timestamp": __import__("time").time()}

        result = client.query_by_cwe("CWE-120", max_results=5)
        assert result == test_data
        # Should NOT have made HTTP request
        client._client.get.assert_not_called()

    def test_expired_cache_miss(self):
        """Expired cache entries should trigger fresh query."""
        client = CVEClient.__new__(CVEClient)
        client._cache = {}
        client._dirty = False
        client._client = MagicMock()
        client.api_key = None
        client._last_request_time = 0.0

        # Pre-populate with expired entry
        import time
        client._cache["CWE-120:5"] = {
            "data": [{"old": True}],
            "timestamp": time.time() - CACHE_TTL_SECONDS - 100,
        }

        # Mock HTTP response
        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json.return_value = {"vulnerabilities": []}
        client._client.get.return_value = mock_resp

        with patch.object(client, "_rate_limit"):
            result = client.query_by_cwe("CWE-120", max_results=5)

        assert result == []  # Fresh empty result
        client._client.get.assert_called_once()

    def test_persistence_roundtrip(self):
        """Cache should persist to disk and reload."""
        with tempfile.TemporaryDirectory() as tmpdir:
            cache_path = Path(tmpdir) / "cve_cache.json"
            test_data = {"CWE-78:3": {"data": [{"cve_id": "CVE-test"}], "timestamp": __import__("time").time()}}

            # Write
            cache_path.write_text(json.dumps(test_data))

            # Load into new client
            client = CVEClient.__new__(CVEClient)
            client._cache = {}
            client._dirty = False
            client._client = MagicMock()
            client.api_key = None
            client._last_request_time = 0.0

            with patch("core.cve_client.CACHE_FILE", cache_path):
                client._load_disk_cache()

            assert "CWE-78:3" in client._cache
            assert client._cache["CWE-78:3"]["data"][0]["cve_id"] == "CVE-test"

    def test_flush_writes_to_disk(self):
        """Dirty cache should flush to disk."""
        with tempfile.TemporaryDirectory() as tmpdir:
            cache_path = Path(tmpdir) / "cve_cache.json"

            client = CVEClient.__new__(CVEClient)
            client._cache = {"test:1": {"data": [], "timestamp": __import__("time").time()}}
            client._dirty = True
            client._client = MagicMock()

            with patch("core.cve_client.CACHE_FILE", cache_path):
                client._flush_disk_cache()

            assert cache_path.exists()
            loaded = json.loads(cache_path.read_text())
            assert "test:1" in loaded
            assert client._dirty is False


class TestCVESummary:
    def test_no_data(self):
        client = CVEClient.__new__(CVEClient)
        client._cache = {}
        client._dirty = False
        client._client = MagicMock()
        client.api_key = None
        client._last_request_time = 0.0

        # Empty cache, mock empty response
        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json.return_value = {"vulnerabilities": []}
        client._client.get.return_value = mock_resp

        with patch.object(client, "_rate_limit"):
            summary = client.get_cve_summary("CWE-9999")
        assert "No CVE data" in summary

    def test_has_known_exploits(self):
        client = CVEClient.__new__(CVEClient)
        client._cache = {}
        client._dirty = False
        client._client = MagicMock()
        client.api_key = None
        client._last_request_time = 0.0

        test_data = [{"severity": "critical", "cvss_score": 9.8}]
        client._cache["CWE-120:3"] = {"data": test_data, "timestamp": __import__("time").time()}

        assert client.has_known_exploits("CWE-120") is True
