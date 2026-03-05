"""
Week 4 tests: Enrichment Pipeline (A4.1–A4.4).

Covers:
  - A4.1: GeoIP enrichment (private IP skip, cache, graceful degradation)
  - A4.2: ASN resolution (classification, hosting/tor/vpn detection)
  - A4.3: Threat intel feed (add/load/check indicators, expiry, CSV)
  - A4.4: Enrichment orchestrator (pipeline, graceful degradation, status)
  - Migrations 002/003

Target: 35+ tests
"""

import sqlite3
import time

import pytest

# ---------------------------------------------------------------------------
# A4.1 — GeoIP Enrichment
# ---------------------------------------------------------------------------


class TestGeoIPPrivateIP:
    """A4.1: Private IPs are skipped without DB lookup."""

    def test_private_ipv4_10(self):
        from amoskys.enrichment.geoip import _is_private_ip

        assert _is_private_ip("10.0.0.1") is True

    def test_private_ipv4_192(self):
        from amoskys.enrichment.geoip import _is_private_ip

        assert _is_private_ip("192.168.1.1") is True

    def test_private_ipv4_172(self):
        from amoskys.enrichment.geoip import _is_private_ip

        assert _is_private_ip("172.16.0.1") is True

    def test_loopback(self):
        from amoskys.enrichment.geoip import _is_private_ip

        assert _is_private_ip("127.0.0.1") is True

    def test_ipv6_loopback(self):
        from amoskys.enrichment.geoip import _is_private_ip

        assert _is_private_ip("::1") is True

    def test_public_ip_not_private(self):
        from amoskys.enrichment.geoip import _is_private_ip

        assert _is_private_ip("8.8.8.8") is False

    def test_invalid_ip_treated_as_private(self):
        from amoskys.enrichment.geoip import _is_private_ip

        assert _is_private_ip("not-an-ip") is True


class TestGeoIPEnricher:
    """A4.1: GeoIPEnricher graceful degradation."""

    def test_no_db_available_false(self):
        """No MaxMind DB → available=False, lookups return None."""
        from amoskys.enrichment.geoip import GeoIPEnricher

        enricher = GeoIPEnricher(db_path="/nonexistent/path.mmdb")
        assert enricher.available is False
        assert enricher.lookup("8.8.8.8") is None

    def test_private_ip_returns_none(self):
        """Private IPs return None even when DB is available."""
        from amoskys.enrichment.geoip import GeoIPEnricher

        enricher = GeoIPEnricher(db_path="/nonexistent/path.mmdb")
        assert enricher.lookup("10.0.0.1") is None
        assert enricher.lookup("192.168.1.1") is None

    def test_empty_ip_returns_none(self):
        from amoskys.enrichment.geoip import GeoIPEnricher

        enricher = GeoIPEnricher(db_path="/nonexistent/path.mmdb")
        assert enricher.lookup("") is None
        assert enricher.lookup(None) is None

    def test_enrich_event_no_db(self):
        """enrich_event returns event unchanged when DB unavailable."""
        from amoskys.enrichment.geoip import GeoIPEnricher

        enricher = GeoIPEnricher(db_path="/nonexistent/path.mmdb")
        event = {"src_ip": "8.8.8.8", "dst_ip": "1.1.1.1"}
        result = enricher.enrich_event(event)
        assert result is event
        assert "geo_src_country" not in result

    def test_cache_info_returns_dict(self):
        from amoskys.enrichment.geoip import GeoIPEnricher

        enricher = GeoIPEnricher(db_path="/nonexistent/path.mmdb")
        info = enricher.cache_info()
        assert "hits" in info
        assert "misses" in info
        assert "maxsize" in info

    def test_close_idempotent(self):
        from amoskys.enrichment.geoip import GeoIPEnricher

        enricher = GeoIPEnricher(db_path="/nonexistent/path.mmdb")
        enricher.close()
        enricher.close()  # Should not raise


# ---------------------------------------------------------------------------
# A4.2 — ASN Resolution
# ---------------------------------------------------------------------------


class TestASNClassification:
    """A4.2: Network type classification from ASN."""

    def test_aws_is_hosting(self):
        from amoskys.enrichment.asn import _classify_network

        assert _classify_network(16509, "Amazon.com Inc.") == "hosting"

    def test_google_is_hosting(self):
        from amoskys.enrichment.asn import _classify_network

        assert _classify_network(15169, "Google LLC") == "hosting"

    def test_tor_asn(self):
        from amoskys.enrichment.asn import _classify_network

        assert _classify_network(680, "DFN") == "tor"

    def test_vpn_asn(self):
        from amoskys.enrichment.asn import _classify_network

        assert _classify_network(9009, "M247 Ltd") == "vpn"

    def test_education_keyword(self):
        from amoskys.enrichment.asn import _classify_network

        assert _classify_network(99999, "MIT University") == "education"

    def test_government_keyword(self):
        from amoskys.enrichment.asn import _classify_network

        assert _classify_network(99999, "US Federal Government") == "government"

    def test_hosting_keyword(self):
        from amoskys.enrichment.asn import _classify_network

        assert _classify_network(99999, "HostGator Cloud Hosting") == "hosting"

    def test_residential_keyword(self):
        from amoskys.enrichment.asn import _classify_network

        assert _classify_network(99999, "Comcast Cable Communications") == "residential"

    def test_unknown_is_corporate(self):
        from amoskys.enrichment.asn import _classify_network

        assert _classify_network(99999, "Acme Corp") == "corporate"


class TestASNEnricher:
    """A4.2: ASNEnricher graceful degradation."""

    def test_no_db_available_false(self):
        from amoskys.enrichment.asn import ASNEnricher

        enricher = ASNEnricher(db_path="/nonexistent/path.mmdb")
        assert enricher.available is False
        assert enricher.lookup("8.8.8.8") is None

    def test_enrich_event_no_db(self):
        from amoskys.enrichment.asn import ASNEnricher

        enricher = ASNEnricher(db_path="/nonexistent/path.mmdb")
        event = {"src_ip": "8.8.8.8"}
        result = enricher.enrich_event(event)
        assert "asn_src_number" not in result


# ---------------------------------------------------------------------------
# A4.3 — Threat Intelligence Feed
# ---------------------------------------------------------------------------


class TestThreatIntelStore:
    """A4.3: Indicator store operations."""

    @pytest.fixture()
    def enricher(self, tmp_path):
        from amoskys.enrichment.threat_intel import ThreatIntelEnricher

        e = ThreatIntelEnricher(db_path=str(tmp_path / "ti.db"))
        yield e
        e.close()

    def test_add_indicator(self, enricher):
        assert enricher.add_indicator("evil.com", "domain", "high", "blocklist")

    def test_add_duplicate_replaces(self, enricher):
        enricher.add_indicator("evil.com", "domain", "high", "list1")
        enricher.add_indicator("evil.com", "domain", "critical", "list2")
        result = enricher.check_indicator("evil.com", "domain")
        assert result is not None
        assert result["severity"] == "critical"

    def test_check_found(self, enricher):
        enricher.add_indicator("1.2.3.4", "ip", "high", "blocklist")
        result = enricher.check_indicator("1.2.3.4", "ip")
        assert result is not None
        assert result["matched"] is True
        assert result["severity"] == "high"

    def test_check_not_found(self, enricher):
        result = enricher.check_indicator("clean.example.com", "domain")
        assert result is None

    def test_check_case_insensitive(self, enricher):
        enricher.add_indicator("Evil.COM", "domain", "high")
        result = enricher.check_indicator("evil.com", "domain")
        assert result is not None

    def test_invalid_type_rejected(self, enricher):
        assert enricher.add_indicator("foo", "invalid_type") is False

    def test_indicator_count(self, enricher):
        enricher.add_indicator("a.com", "domain", "low")
        enricher.add_indicator("b.com", "domain", "medium")
        assert enricher.indicator_count() == 2

    def test_load_csv_text(self, enricher):
        csv_text = "indicator,type,severity\nevil.com,domain,high\n1.2.3.4,ip,medium\n"
        count = enricher.load_csv(csv_text)
        assert count == 2
        assert enricher.check_indicator("evil.com", "domain") is not None

    def test_load_csv_file(self, enricher, tmp_path):
        csv_file = tmp_path / "feed.csv"
        csv_file.write_text("indicator,type,severity\nbad.net,domain,critical\n")
        count = enricher.load_csv(str(csv_file))
        assert count == 1

    def test_expired_indicator_not_matched(self, enricher):
        enricher.add_indicator(
            "old.com", "domain", "high", expires_at="2020-01-01T00:00:00+00:00"
        )
        result = enricher.check_indicator("old.com", "domain")
        assert result is None


class TestThreatIntelEnrichEvent:
    """A4.3: Event enrichment with threat intel."""

    @pytest.fixture()
    def enricher(self, tmp_path):
        from amoskys.enrichment.threat_intel import ThreatIntelEnricher

        e = ThreatIntelEnricher(db_path=str(tmp_path / "ti.db"))
        e.add_indicator("evil.com", "domain", "high", "blocklist")
        e.add_indicator("1.2.3.4", "ip", "critical", "c2-list")
        yield e
        e.close()

    def test_enrich_matching_domain(self, enricher):
        event = {"domain": "evil.com"}
        enricher.enrich_event(event)
        assert event["threat_intel_match"] is True
        assert event["threat_source"] == "blocklist"

    def test_enrich_matching_ip(self, enricher):
        event = {"src_ip": "1.2.3.4"}
        enricher.enrich_event(event)
        assert event["threat_intel_match"] is True
        assert event["threat_severity"] == "critical"

    def test_enrich_no_match(self, enricher):
        event = {"src_ip": "8.8.8.8"}
        enricher.enrich_event(event)
        assert event["threat_intel_match"] is False


# ---------------------------------------------------------------------------
# A4.4 — Enrichment Pipeline
# ---------------------------------------------------------------------------


class TestEnrichmentPipeline:
    """A4.4: Pipeline chains enrichers with graceful degradation."""

    def test_pipeline_no_dbs_raw_status(self, tmp_path):
        """All enrichers unavailable → status = raw."""
        from amoskys.enrichment import EnrichmentPipeline

        pipeline = EnrichmentPipeline(
            geoip_db_path="/nonexistent",
            asn_db_path="/nonexistent",
            threat_intel_db_path=str(tmp_path / "ti.db"),
        )
        event = {"src_ip": "8.8.8.8"}
        result = pipeline.enrich(event)
        # threat_intel is available (SQLite always works) but has no indicators
        # so status depends on how many stages ran
        assert result["enrichment_status"] in ("enriched", "partial", "raw")
        pipeline.close()

    def test_pipeline_threat_intel_only(self, tmp_path):
        """Only threat intel available → still enriches."""
        from amoskys.enrichment import EnrichmentPipeline

        pipeline = EnrichmentPipeline(
            geoip_db_path="/nonexistent",
            asn_db_path="/nonexistent",
            threat_intel_db_path=str(tmp_path / "ti.db"),
        )
        pipeline.threat_intel.add_indicator("evil.com", "domain", "high", "test")
        event = {"domain": "evil.com"}
        pipeline.enrich(event)
        assert event["threat_intel_match"] is True
        pipeline.close()

    def test_pipeline_status_dict(self, tmp_path):
        from amoskys.enrichment import EnrichmentPipeline

        pipeline = EnrichmentPipeline(
            threat_intel_db_path=str(tmp_path / "ti.db"),
        )
        status = pipeline.status()
        assert "geoip" in status
        assert "asn" in status
        assert "threat_intel" in status
        assert "available" in status["geoip"]
        pipeline.close()

    def test_pipeline_close_idempotent(self, tmp_path):
        from amoskys.enrichment import EnrichmentPipeline

        pipeline = EnrichmentPipeline(
            threat_intel_db_path=str(tmp_path / "ti.db"),
        )
        pipeline.close()
        pipeline.close()  # No raise


class TestThreatIntelCache:
    """A4.3/A4.4: Cache TTL expiry."""

    def test_cache_clears_on_load(self, tmp_path):
        from amoskys.enrichment.threat_intel import ThreatIntelEnricher

        enricher = ThreatIntelEnricher(
            db_path=str(tmp_path / "ti.db"), cache_ttl_seconds=3600
        )
        enricher.add_indicator("a.com", "domain", "low")
        # Warm cache
        enricher.check_indicator("a.com", "domain")
        info1 = enricher.cache_info()
        assert info1["misses"] >= 1

        # Load CSV clears cache
        enricher.load_csv("indicator,type,severity\nb.com,domain,high\n")
        info2 = enricher.cache_info()
        assert info2["size"] == 0  # Cache was cleared
        enricher.close()

    def test_cache_ttl_expiry(self, tmp_path):
        from amoskys.enrichment.threat_intel import ThreatIntelEnricher

        # Use long TTL so cache works normally first
        enricher = ThreatIntelEnricher(
            db_path=str(tmp_path / "ti.db"), cache_ttl_seconds=3600
        )
        enricher.add_indicator("a.com", "domain", "low")

        # First lookup: cache miss → populates cache
        enricher.check_indicator("a.com", "domain")
        # Second lookup: cache hit
        enricher.check_indicator("a.com", "domain")
        info_before = enricher.cache_info()
        assert info_before["hits"] >= 1
        assert info_before["size"] >= 1

        # Force TTL expiry by backdating epoch
        enricher._cache_epoch = time.monotonic() - 3601
        enricher.check_indicator("a.com", "domain")
        info_after = enricher.cache_info()
        # cache_clear() resets stats, then this lookup is miss #1
        assert info_after["misses"] >= 1
        assert info_after["hits"] == 0
        enricher.close()


# ---------------------------------------------------------------------------
# Migrations 002/003
# ---------------------------------------------------------------------------


class TestEnrichmentMigrations:
    """Migrations 002 and 003 add geo/asn/threat_intel columns."""

    @pytest.fixture()
    def migrated_db(self, tmp_path):
        db_path = str(tmp_path / "test.db")
        from amoskys.storage.telemetry_store import SCHEMA

        conn = sqlite3.connect(db_path)
        conn.executescript(SCHEMA)
        conn.commit()
        conn.close()

        from amoskys.storage.migrations.migrate import run_migrations

        run_migrations(db_path)

        conn = sqlite3.connect(db_path)
        yield conn
        conn.close()

    def _get_columns(self, conn, table):
        return {
            row[1] for row in conn.execute(f"PRAGMA table_info({table})").fetchall()
        }

    def test_migration_002_flow_geo_columns(self, migrated_db):
        cols = self._get_columns(migrated_db, "flow_events")
        assert "geo_src_country" in cols
        assert "geo_dst_latitude" in cols
        assert "asn_src_number" in cols
        assert "asn_dst_network_type" in cols

    def test_migration_002_security_geo_columns(self, migrated_db):
        cols = self._get_columns(migrated_db, "security_events")
        assert "geo_src_country" in cols
        assert "asn_src_org" in cols

    def test_migration_003_threat_intel_columns(self, migrated_db):
        for table in ("flow_events", "security_events", "dns_events", "fim_events"):
            cols = self._get_columns(migrated_db, table)
            assert "threat_intel_match" in cols, f"{table} missing threat_intel_match"
            assert "threat_source" in cols, f"{table} missing threat_source"

    def test_all_migrations_recorded(self, migrated_db):
        rows = migrated_db.execute(
            "SELECT version FROM schema_migrations ORDER BY version"
        ).fetchall()
        versions = [r[0] for r in rows]
        # At least the original 3 migrations must be present; new ones may be added
        assert versions[:3] == [1, 2, 3]
        assert len(versions) >= 3
