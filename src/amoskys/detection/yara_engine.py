"""AMOSKYS YARA Rule Engine — file and memory scanning for threat detection.

YARA rules provide pattern matching for:
    - Malware identification (known signatures)
    - Webshell detection (PHP/JSP/ASP patterns)
    - Credential file detection (private keys, tokens)
    - Suspicious binary patterns (packed, obfuscated)

Rule directory: detection/rules/yara/

Usage:
    engine = YARAEngine()
    loaded = engine.load_rules("src/amoskys/detection/rules/yara/")
    matches = engine.scan_file("/path/to/suspicious/file")
    # matches = engine.scan_data(raw_bytes)

Note: Requires the `yara-python` package for compiled rule evaluation.
If not installed, the engine operates in metadata-only mode (can load
and report coverage but cannot scan).
"""

from __future__ import annotations

import logging
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

logger = logging.getLogger(__name__)

try:
    import yara

    YARA_AVAILABLE = True
except ImportError:
    yara = None  # type: ignore
    YARA_AVAILABLE = False
    logger.info(
        "yara-python not installed — YARA scanning disabled, metadata mode only"
    )


# ── Data Models ──────────────────────────────────────────────────────────────


@dataclass
class YARARuleMeta:
    """Metadata for a loaded YARA rule (parsed from rule file header)."""

    name: str
    description: str = ""
    author: str = ""
    reference: str = ""
    severity: str = "medium"  # informational | low | medium | high | critical
    mitre_techniques: List[str] = field(default_factory=list)
    mitre_tactics: List[str] = field(default_factory=list)
    confidence: float = 0.7
    file_path: str = ""
    tags: List[str] = field(default_factory=list)


@dataclass
class YARAMatch:
    """Result of a YARA rule matching against data."""

    rule_name: str
    description: str
    severity: str
    confidence: float
    mitre_techniques: List[str]
    mitre_tactics: List[str]
    matched_strings: List[str]  # String identifiers that matched
    matched_data: List[str]  # Actual matched byte sequences (hex)
    scan_target: str  # File path or "memory:<pid>"
    timestamp_ns: int
    tags: List[str] = field(default_factory=list)


@dataclass
class YARACoverage:
    """MITRE coverage report for loaded YARA rules."""

    technique_to_rules: Dict[str, List[str]]
    tactic_to_rules: Dict[str, List[str]]
    total_rules: int
    total_techniques: int
    total_tactics: int


# ── YARA Engine ──────────────────────────────────────────────────────────────


class YARAEngine:
    """YARA rule scanning for file-based and data-based detection.

    Operates in two modes:
        - Full mode (yara-python installed): Can compile and scan
        - Metadata mode (no yara-python): Can load rule metadata for coverage
          reporting but cannot scan
    """

    def __init__(self) -> None:
        self._rule_meta: Dict[str, YARARuleMeta] = {}  # name → metadata
        self._compiled_rules: Optional[Any] = None  # yara.Rules object
        self._rule_sources: Dict[str, str] = {}  # namespace → file path
        self._match_count: Dict[str, int] = {}
        self._last_match: Dict[str, int] = {}
        self._scan_count: int = 0
        self._scan_errors: int = 0

    @property
    def rule_count(self) -> int:
        """Number of loaded rules."""
        return len(self._rule_meta)

    @property
    def can_scan(self) -> bool:
        """Whether the engine can actually scan (yara-python installed)."""
        return YARA_AVAILABLE and self._compiled_rules is not None

    def load_rules(self, rules_dir: str) -> int:
        """Load all .yar/.yara rules from directory (recursive).

        Loads rule metadata from comments/meta sections. If yara-python is
        available, also compiles rules for scanning.

        Args:
            rules_dir: Path to directory containing YARA rules.

        Returns:
            Number of rules successfully loaded.
        """
        rules_path = Path(rules_dir)
        if not rules_path.is_dir():
            logger.error("YARA rules directory not found: %s", rules_dir)
            return 0

        yara_files: Dict[str, str] = {}
        loaded = 0

        for rule_file in sorted(rules_path.rglob("*")):
            if rule_file.suffix not in (".yar", ".yara"):
                continue

            try:
                meta = self._parse_rule_metadata(rule_file)
                for m in meta:
                    self._rule_meta[m.name] = m
                    self._match_count[m.name] = 0
                    loaded += len(meta)

                namespace = rule_file.stem
                yara_files[namespace] = str(rule_file)
                self._rule_sources[namespace] = str(rule_file)

            except Exception as e:
                logger.warning(
                    "Failed to parse YARA metadata from %s: %s", rule_file.name, e
                )

        # Compile rules if yara-python available
        if YARA_AVAILABLE and yara_files:
            try:
                self._compiled_rules = yara.compile(filepaths=yara_files)
                logger.info(
                    "YARA engine: compiled %d rule files (%d rules) from %s",
                    len(yara_files),
                    loaded,
                    rules_dir,
                )
            except Exception as e:
                logger.error("YARA compilation failed: %s", e)
                self._compiled_rules = None
        else:
            logger.info(
                "YARA engine: loaded %d rule metadata (scan %s) from %s",
                loaded,
                "enabled" if YARA_AVAILABLE else "disabled",
                rules_dir,
            )

        return loaded

    def scan_file(self, path: str, timeout: int = 60) -> List[YARAMatch]:
        """Scan a file against all loaded YARA rules.

        Args:
            path: Path to file to scan.
            timeout: Maximum scan time in seconds.

        Returns:
            List of YARAMatch for rules that matched.
        """
        if not self.can_scan:
            logger.debug(
                "YARA scanning not available (yara-python not installed or no rules)"
            )
            return []

        if not os.path.isfile(path):
            logger.warning("File not found for YARA scan: %s", path)
            return []

        self._scan_count += 1
        matches: List[YARAMatch] = []

        try:
            yara_matches = self._compiled_rules.match(path, timeout=timeout)
            for m in yara_matches:
                match = self._yara_match_to_result(m, path)
                matches.append(match)
                self._match_count[m.rule] = self._match_count.get(m.rule, 0) + 1
                self._last_match[m.rule] = match.timestamp_ns
        except Exception as e:
            logger.error("YARA scan failed for %s: %s", path, e)
            self._scan_errors += 1

        return matches

    def scan_data(self, data: bytes, source: str = "<data>") -> List[YARAMatch]:
        """Scan raw bytes against all loaded YARA rules.

        Args:
            data: Raw bytes to scan.
            source: Description of data source for logging.

        Returns:
            List of YARAMatch for rules that matched.
        """
        if not self.can_scan:
            return []

        self._scan_count += 1
        matches: List[YARAMatch] = []

        try:
            yara_matches = self._compiled_rules.match(data=data)
            for m in yara_matches:
                match = self._yara_match_to_result(m, source)
                matches.append(match)
                self._match_count[m.rule] = self._match_count.get(m.rule, 0) + 1
                self._last_match[m.rule] = match.timestamp_ns
        except Exception as e:
            logger.error("YARA data scan failed for %s: %s", source, e)
            self._scan_errors += 1

        return matches

    def get_coverage(self) -> YARACoverage:
        """Generate MITRE ATT&CK coverage report from loaded rules."""
        technique_to_rules: Dict[str, List[str]] = {}
        tactic_to_rules: Dict[str, List[str]] = {}

        for meta in self._rule_meta.values():
            for tech in meta.mitre_techniques:
                technique_to_rules.setdefault(tech, []).append(meta.name)
            for tactic in meta.mitre_tactics:
                tactic_to_rules.setdefault(tactic, []).append(meta.name)

        return YARACoverage(
            technique_to_rules=technique_to_rules,
            tactic_to_rules=tactic_to_rules,
            total_rules=len(self._rule_meta),
            total_techniques=len(technique_to_rules),
            total_tactics=len(tactic_to_rules),
        )

    def get_rule_metrics(self, rule_name: str) -> Dict[str, Any]:
        """Get match metrics for a specific rule."""
        return {
            "rule_name": rule_name,
            "match_count": self._match_count.get(rule_name, 0),
            "last_match_ns": self._last_match.get(rule_name, 0),
            "exists": rule_name in self._rule_meta,
        }

    def get_scan_stats(self) -> Dict[str, Any]:
        """Get overall scan statistics."""
        return {
            "total_scans": self._scan_count,
            "total_errors": self._scan_errors,
            "rules_loaded": len(self._rule_meta),
            "can_scan": self.can_scan,
        }

    # ── Internal ─────────────────────────────────────────────────────────

    def _parse_rule_metadata(self, path: Path) -> List[YARARuleMeta]:
        """Extract metadata from YARA rule file meta sections."""
        content = path.read_text()
        metas: List[YARARuleMeta] = []

        # Parse rule names and meta blocks
        # Pattern: rule <name> { meta: ... }
        import re

        rule_pattern = re.compile(
            r"rule\s+(\w+)\s*(?::\s*([\w\s]+))?\s*\{", re.MULTILINE
        )
        meta_pattern = re.compile(
            r"meta\s*:\s*(.*?)(?:strings|condition)\s*:",
            re.DOTALL | re.MULTILINE,
        )

        for rule_match in rule_pattern.finditer(content):
            rule_name = rule_match.group(1)
            rule_tags = (rule_match.group(2) or "").split()

            # Find meta block after this rule
            remaining = content[rule_match.end() :]
            meta_match = meta_pattern.search(remaining)

            meta = YARARuleMeta(
                name=rule_name,
                file_path=str(path),
                tags=rule_tags,
            )

            if meta_match:
                meta_text = meta_match.group(1)
                meta = self._parse_meta_block(meta_text, meta)

            metas.append(meta)

        return metas

    @staticmethod
    def _parse_meta_block(meta_text: str, meta: YARARuleMeta) -> YARARuleMeta:
        """Parse key = "value" pairs from a YARA meta block."""
        import re

        for line in meta_text.split("\n"):
            line = line.strip()
            kv_match = re.match(r'(\w+)\s*=\s*"([^"]*)"', line)
            if not kv_match:
                continue

            key = kv_match.group(1).lower()
            value = kv_match.group(2)

            if key == "description":
                meta.description = value
            elif key == "author":
                meta.author = value
            elif key == "reference":
                meta.reference = value
            elif key == "severity":
                meta.severity = value
            elif key == "confidence":
                try:
                    meta.confidence = float(value)
                except ValueError:
                    pass
            elif key == "mitre_technique":
                meta.mitre_techniques.append(value.upper())
            elif key == "mitre_tactic":
                meta.mitre_tactics.append(value)

        return meta

    def _yara_match_to_result(self, yara_match: Any, target: str) -> YARAMatch:
        """Convert a yara.Match object to our YARAMatch dataclass."""
        now_ns = int(time.time() * 1e9)

        rule_name = yara_match.rule
        meta = self._rule_meta.get(rule_name, YARARuleMeta(name=rule_name))

        matched_strings = []
        matched_data = []
        if hasattr(yara_match, "strings"):
            for s in yara_match.strings:
                if hasattr(s, "identifier"):
                    matched_strings.append(s.identifier)
                if hasattr(s, "instances"):
                    for inst in s.instances:
                        matched_data.append(inst.matched_data.hex()[:64])

        return YARAMatch(
            rule_name=rule_name,
            description=meta.description,
            severity=meta.severity,
            confidence=meta.confidence,
            mitre_techniques=meta.mitre_techniques,
            mitre_tactics=meta.mitre_tactics,
            matched_strings=matched_strings,
            matched_data=matched_data,
            scan_target=target,
            timestamp_ns=now_ns,
            tags=list(getattr(yara_match, "tags", [])),
        )
