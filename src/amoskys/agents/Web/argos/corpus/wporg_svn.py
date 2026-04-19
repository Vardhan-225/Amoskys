"""WordPress.org plugin corpus — fetch + cache + iterate.

wordpress.org exposes every plugin release three ways:

  1. ZIP download:   https://downloads.wordpress.org/plugin/<slug>.<version>.zip
  2. "Latest stable": https://downloads.wordpress.org/plugin/<slug>.latest-stable.zip
  3. Info API:       https://api.wordpress.org/plugins/info/1.2/

No auth, no API key, no rate-limit gate for reasonable use. This module
is the door Argos uses to read the ~60,000-plugin universe as raw PHP
source and ship it to the AST scanners.

Cache layout (default ~/.argos/corpus):

    corpus/
      zips/<slug>.<version>.zip
      extracted/<slug>/<version>/
      index.json          # slug -> {latest_seen, active_installs, last_fetched_ns}
      top_by_installs.json  # cached API response

Usage:

    corpus = WPOrgCorpus()
    source = corpus.fetch("contact-form-7", "5.9.0")
    for php_file in source.iter_php():
        ...

    for source in corpus.iter_top(n=100):  # top 100 by install count
        ...
"""

from __future__ import annotations

import io
import json
import logging
import os
import shutil
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator, List, Optional, Tuple

logger = logging.getLogger("amoskys.argos.corpus")


# ── Constants ──────────────────────────────────────────────────────

WP_DOWNLOADS_BASE = "https://downloads.wordpress.org/plugin"
WP_API_BASE = "https://api.wordpress.org/plugins/info/1.2/"
DEFAULT_USER_AGENT = "Argos/0.1 (+https://amoskys.com/argos; security-research)"

# wp.org ZIPs are reasonable in size but a few outliers (Elementor Pro,
# Jetpack) push 20-40 MB. Cap at 200 MB to reject anything pathological.
MAX_ZIP_BYTES = 200 * 1024 * 1024


# ── Exceptions ─────────────────────────────────────────────────────

class WPOrgCorpusError(RuntimeError):
    """Anything that goes wrong fetching or unpacking a plugin."""


# ── Data ───────────────────────────────────────────────────────────

@dataclass
class PluginSource:
    """One extracted plugin on disk.

    `plugin_root` is the directory the scanner operates on — the folder
    that contains the main plugin PHP file (and typically `includes/`,
    `admin/`, `public/`, etc.).
    """

    slug: str
    version: str
    extracted_root: Path  # the /extracted/<slug>/<version>/ dir
    plugin_root: Path     # where the actual plugin code lives (strip one level if wrapped)
    active_installs: Optional[int] = None
    fetched_at_ns: int = field(default_factory=lambda: int(time.time() * 1e9))

    def iter_php(self) -> Iterator[Path]:
        """Yield every .php file under plugin_root, skipping vendor + node_modules."""
        for path in self.plugin_root.rglob("*.php"):
            if any(seg in path.parts for seg in ("vendor", "node_modules", "tests")):
                continue
            yield path

    def file_count(self) -> int:
        return sum(1 for _ in self.iter_php())

    def total_bytes(self) -> int:
        return sum(p.stat().st_size for p in self.iter_php())


# ── Core ───────────────────────────────────────────────────────────

class WPOrgCorpus:
    """Fetcher + cache manager for wordpress.org plugin source.

    Thread-safe for reads; concurrent writes to the same (slug, version)
    are serialized by atomic rename of a temp directory. The download
    itself is not parallelized here — callers who want concurrency
    should wrap `fetch()` in their own executor.
    """

    def __init__(
        self,
        cache_dir: Optional[Path] = None,
        user_agent: str = DEFAULT_USER_AGENT,
        request_timeout_s: float = 30.0,
    ) -> None:
        self.cache_dir = Path(cache_dir or Path.home() / ".argos" / "corpus").resolve()
        self.zips_dir = self.cache_dir / "zips"
        self.extracted_dir = self.cache_dir / "extracted"
        self.index_path = self.cache_dir / "index.json"
        self.top_cache_path = self.cache_dir / "top_by_installs.json"

        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.zips_dir.mkdir(parents=True, exist_ok=True)
        self.extracted_dir.mkdir(parents=True, exist_ok=True)

        self.user_agent = user_agent
        self.request_timeout_s = request_timeout_s

    # ─────────────────────────── public API

    def fetch(self, slug: str, version: Optional[str] = None) -> PluginSource:
        """Fetch a plugin at a specific version (or latest if version is None).

        Idempotent: subsequent calls for the same (slug, version) return
        the cached extraction without re-downloading.
        """
        self._validate_slug(slug)
        if version is None:
            version = self._resolve_latest_version(slug)

        extract_root = self.extracted_dir / slug / version
        plugin_root = self._plugin_root_within(extract_root) if extract_root.exists() else None

        if plugin_root is None:
            zip_path = self._download_zip(slug, version)
            extract_root = self._extract_zip(zip_path, slug, version)
            plugin_root = self._plugin_root_within(extract_root)

        self._update_index(slug, version)

        return PluginSource(
            slug=slug,
            version=version,
            extracted_root=extract_root,
            plugin_root=plugin_root,
            active_installs=self._lookup_active_installs(slug),
        )

    def iter_top(self, n: int = 100, min_installs: int = 1000) -> Iterator[PluginSource]:
        """Yield the top-n plugins by active-install count, fetched lazily.

        Uses the cached wp.org API response if fresh (<24h); otherwise
        refreshes. Plugins below `min_installs` are filtered out — the
        bounty-relevant floor is ~1,000 active installs.
        """
        top = self.top_by_installs(n=n, min_installs=min_installs)
        for slug, installs in top:
            try:
                source = self.fetch(slug)
                source.active_installs = installs
                yield source
            except WPOrgCorpusError as e:
                logger.warning("corpus: skipping %s — %s", slug, e)

    def top_by_installs(
        self,
        n: int = 100,
        min_installs: int = 1000,
        refresh: bool = False,
    ) -> List[Tuple[str, int]]:
        """Return [(slug, active_installs), ...] sorted descending.

        The wp.org API paginates at 250 results per page and sorts by
        popularity natively, so page=1 already yields the highest-install
        plugins.
        """
        if not refresh and self.top_cache_path.exists():
            age_s = time.time() - self.top_cache_path.stat().st_mtime
            if age_s < 86_400:
                try:
                    cached = json.loads(self.top_cache_path.read_text())
                    filtered = [(s, i) for s, i in cached if i >= min_installs]
                    return filtered[:n]
                except (json.JSONDecodeError, ValueError):
                    pass  # fall through to refresh

        per_page = min(250, max(n, 100))
        params = {
            "action": "query_plugins",
            "request[per_page]": str(per_page),
            "request[page]": "1",
            "request[browse]": "popular",
            "request[fields][active_installs]": "true",
            "request[fields][versions]": "false",
            "request[fields][sections]": "false",
            "request[fields][description]": "false",
        }
        url = f"{WP_API_BASE}?{urllib.parse.urlencode(params)}"

        try:
            raw = self._http_get(url)
            data = json.loads(raw.decode("utf-8"))
        except (urllib.error.URLError, json.JSONDecodeError) as e:
            raise WPOrgCorpusError(f"wp.org API query failed: {e}") from e

        entries: List[Tuple[str, int]] = []
        for plugin in data.get("plugins", []):
            slug = plugin.get("slug")
            installs = plugin.get("active_installs") or 0
            if slug and installs >= min_installs:
                entries.append((slug, int(installs)))
        entries.sort(key=lambda x: x[1], reverse=True)

        try:
            self.top_cache_path.write_text(json.dumps(entries))
        except OSError:
            pass  # cache write failure is non-fatal

        return entries[:n]

    def clear(self, slug: Optional[str] = None) -> int:
        """Remove cache entries. Returns bytes freed.

        If `slug` is given, only that plugin's cache is removed.
        Otherwise the entire corpus cache is wiped.
        """
        freed = 0
        targets: List[Path] = []
        if slug is None:
            targets = [self.zips_dir, self.extracted_dir]
        else:
            self._validate_slug(slug)
            targets = [self.zips_dir / slug, self.extracted_dir / slug]
            for zip_path in self.zips_dir.glob(f"{slug}.*.zip"):
                targets.append(zip_path)

        for path in targets:
            if path.exists():
                freed += self._dir_size(path) if path.is_dir() else path.stat().st_size
                if path.is_dir():
                    shutil.rmtree(path, ignore_errors=True)
                else:
                    path.unlink(missing_ok=True)

        if slug is None:
            self.zips_dir.mkdir(parents=True, exist_ok=True)
            self.extracted_dir.mkdir(parents=True, exist_ok=True)

        return freed

    # ─────────────────────────── internals

    def _resolve_latest_version(self, slug: str) -> str:
        params = {
            "action": "plugin_information",
            "request[slug]": slug,
            "request[fields][versions]": "false",
            "request[fields][sections]": "false",
        }
        url = f"{WP_API_BASE}?{urllib.parse.urlencode(params)}"
        try:
            raw = self._http_get(url)
            data = json.loads(raw.decode("utf-8"))
        except (urllib.error.URLError, json.JSONDecodeError) as e:
            raise WPOrgCorpusError(f"wp.org info lookup failed for {slug}: {e}") from e

        version = data.get("version")
        if not version or not isinstance(version, str):
            raise WPOrgCorpusError(
                f"wp.org returned no stable version for {slug} "
                f"(plugin closed/removed/new?): {data.get('error') or '<no error field>'}"
            )
        return version

    def _download_zip(self, slug: str, version: str) -> Path:
        zip_path = self.zips_dir / f"{slug}.{version}.zip"
        if zip_path.exists() and zip_path.stat().st_size > 0:
            return zip_path

        url = f"{WP_DOWNLOADS_BASE}/{slug}.{version}.zip"
        logger.info("corpus: fetching %s", url)

        try:
            raw = self._http_get(url, max_bytes=MAX_ZIP_BYTES)
        except urllib.error.HTTPError as e:
            raise WPOrgCorpusError(
                f"download failed for {slug}@{version} (HTTP {e.code}): "
                f"{'version may not exist' if e.code == 404 else e.reason}"
            ) from e
        except urllib.error.URLError as e:
            raise WPOrgCorpusError(f"download failed for {slug}@{version}: {e.reason}") from e

        # Write atomically so a partial file never appears cached.
        tmp = zip_path.with_suffix(".zip.partial")
        tmp.write_bytes(raw)
        tmp.replace(zip_path)
        return zip_path

    def _extract_zip(self, zip_path: Path, slug: str, version: str) -> Path:
        target = self.extracted_dir / slug / version
        if target.exists():
            return target

        # Extract to a temp sibling, then atomic-rename. Avoids leaving a
        # half-extracted tree if we crash partway through.
        target.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=target.parent, prefix=f".{version}.extract.") as td:
            tmp_root = Path(td)
            try:
                with zipfile.ZipFile(zip_path) as zf:
                    for member in zf.infolist():
                        # Zip-slip hardening: reject any member that
                        # resolves outside our target directory.
                        resolved = (tmp_root / member.filename).resolve()
                        if not str(resolved).startswith(str(tmp_root.resolve())):
                            raise WPOrgCorpusError(
                                f"refusing zip-slip member in {zip_path.name}: {member.filename}"
                            )
                        zf.extract(member, tmp_root)
            except zipfile.BadZipFile as e:
                raise WPOrgCorpusError(f"corrupt zip for {slug}@{version}: {e}") from e

            # zip typically wraps everything in a single dir named <slug>/.
            # Move that child up to become target.
            children = [c for c in tmp_root.iterdir() if c.is_dir()]
            if len(children) == 1 and children[0].name == slug:
                children[0].rename(target)
            else:
                tmp_root.rename(target)

        return target

    def _plugin_root_within(self, extract_root: Path) -> Path:
        """Locate the real plugin directory inside the extraction.

        Usually this *is* extract_root (when we unwrap the single-dir
        wrapping inside _extract_zip). But some plugin ZIPs are flat at
        the root — handle both shapes.
        """
        if not extract_root.exists():
            raise WPOrgCorpusError(f"extract root missing: {extract_root}")

        # If extract_root contains a single child dir and no .php files
        # directly, descend into the child (handles weird double-wrap).
        entries = list(extract_root.iterdir())
        has_direct_php = any(p.suffix == ".php" for p in entries if p.is_file())
        dirs = [p for p in entries if p.is_dir()]

        if not has_direct_php and len(dirs) == 1:
            return dirs[0]
        return extract_root

    def _update_index(self, slug: str, version: str) -> None:
        index: dict = {}
        if self.index_path.exists():
            try:
                index = json.loads(self.index_path.read_text())
            except (json.JSONDecodeError, OSError):
                index = {}
        entry = index.get(slug, {})
        entry["latest_seen"] = version
        entry["last_fetched_ns"] = int(time.time() * 1e9)
        index[slug] = entry
        try:
            self.index_path.write_text(json.dumps(index, indent=2, sort_keys=True))
        except OSError:
            pass

    def _lookup_active_installs(self, slug: str) -> Optional[int]:
        if not self.top_cache_path.exists():
            return None
        try:
            cached = json.loads(self.top_cache_path.read_text())
        except (json.JSONDecodeError, OSError):
            return None
        for s, installs in cached:
            if s == slug:
                return int(installs)
        return None

    def _http_get(self, url: str, max_bytes: int = 10 * 1024 * 1024) -> bytes:
        req = urllib.request.Request(url, headers={"User-Agent": self.user_agent})
        with urllib.request.urlopen(req, timeout=self.request_timeout_s) as resp:
            buf = io.BytesIO()
            total = 0
            chunk_size = 64 * 1024
            while True:
                chunk = resp.read(chunk_size)
                if not chunk:
                    break
                total += len(chunk)
                if total > max_bytes:
                    raise WPOrgCorpusError(
                        f"response exceeded max_bytes={max_bytes} for {url}"
                    )
                buf.write(chunk)
            return buf.getvalue()

    @staticmethod
    def _validate_slug(slug: str) -> None:
        # wp.org plugin slugs are lowercase alnum + dashes. Guard against
        # path traversal before it reaches the cache dir.
        if not slug or not all(c.isalnum() or c in "-_" for c in slug):
            raise WPOrgCorpusError(f"invalid plugin slug: {slug!r}")
        if slug.startswith("-") or slug.startswith("_") or slug.startswith("."):
            raise WPOrgCorpusError(f"invalid plugin slug: {slug!r}")

    @staticmethod
    def _dir_size(path: Path) -> int:
        total = 0
        for root, _dirs, files in os.walk(path):
            for f in files:
                try:
                    total += os.path.getsize(os.path.join(root, f))
                except OSError:
                    pass
        return total
