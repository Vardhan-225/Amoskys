/**
 * AMOSKYS Dashboard Core — shared utilities for all Observatory pages.
 *
 * Provides:
 *  - DashboardCache: client-side TTL cache for API responses
 *  - DashboardPoller: visibility-aware polling with priority tiers
 *  - LazyLoader: IntersectionObserver-based deferred loading
 *  - riskColor / riskClass: severity color helpers
 *  - formatNumber: human-readable number formatting
 *  - Chart.js defaults for dark theme
 */

// ── Client-side cache ──────────────────────────────────────────────
const DashboardCache = {
    _cache: new Map(),
    _ttl: new Map(),
    _inflight: new Map(),

    /**
     * Fetch with cache.  Coalesces concurrent requests to the same URL.
     * @param {string} url
     * @param {number} ttlSeconds - cache lifetime (default 30s)
     * @returns {Promise<any>}
     */
    async fetch(url, ttlSeconds = 30) {
        const now = Date.now();
        if (this._cache.has(url) && this._ttl.get(url) > now) {
            return this._cache.get(url);
        }
        // Coalesce in-flight requests
        if (this._inflight.has(url)) {
            return this._inflight.get(url);
        }
        const promise = fetch(url)
            .then(r => { if (!r.ok) throw new Error(r.status); return r.json(); })
            .then(data => {
                this._cache.set(url, data);
                this._ttl.set(url, now + ttlSeconds * 1000);
                this._inflight.delete(url);
                return data;
            })
            .catch(err => {
                this._inflight.delete(url);
                throw err;
            });
        this._inflight.set(url, promise);
        return promise;
    },

    invalidate(urlPrefix) {
        if (!urlPrefix) { this._cache.clear(); this._ttl.clear(); return; }
        for (const key of this._cache.keys()) {
            if (key.startsWith(urlPrefix)) {
                this._cache.delete(key);
                this._ttl.delete(key);
            }
        }
    }
};


// ── Visibility-aware poller ────────────────────────────────────────
class DashboardPoller {
    /**
     * @param {Array<{url: string, callback: Function, priority?: string, ttl?: number}>} endpoints
     * @param {number} intervalMs - poll interval (default 30000)
     */
    constructor(endpoints, intervalMs = 30000) {
        this.endpoints = endpoints;
        this.interval = intervalMs;
        this.timerId = null;
        this.isVisible = true;

        document.addEventListener('visibilitychange', () => {
            this.isVisible = !document.hidden;
            if (this.isVisible) this.poll();
        });
    }

    async poll() {
        if (!this.isVisible) return;

        const high = this.endpoints.filter(e => e.priority === 'high');
        const low  = this.endpoints.filter(e => e.priority !== 'high');

        // High-priority first (KPIs)
        await Promise.allSettled(high.map(async ep => {
            try {
                const data = await DashboardCache.fetch(ep.url, ep.ttl || 25);
                ep.callback(data);
            } catch (err) {
                console.warn(`Poll failed: ${ep.url}`, err);
            }
        }));

        // Then low-priority (charts, tables)
        await Promise.allSettled(low.map(async ep => {
            try {
                const data = await DashboardCache.fetch(ep.url, ep.ttl || 55);
                ep.callback(data);
            } catch (err) {
                console.warn(`Poll failed: ${ep.url}`, err);
            }
        }));
    }

    start() {
        this.poll();
        this.timerId = setInterval(() => this.poll(), this.interval);
        return this;
    }

    stop() {
        if (this.timerId) { clearInterval(this.timerId); this.timerId = null; }
    }
}


// ── Lazy loader ────────────────────────────────────────────────────
class LazyLoader {
    /**
     * Defer loading of a section until it scrolls into view.
     * @param {string} selector - CSS selector for the trigger element
     * @param {Function} loadFn  - called once when element is visible
     */
    static observe(selector, loadFn) {
        const el = document.querySelector(selector);
        if (!el) return;
        const observer = new IntersectionObserver((entries) => {
            entries.forEach(entry => {
                if (entry.isIntersecting) {
                    loadFn();
                    observer.unobserve(entry.target);
                }
            });
        }, { rootMargin: '200px' });
        observer.observe(el);
    }
}


// ── Color helpers ──────────────────────────────────────────────────

/**
 * Severity-based risk color (industry standard).
 * @param {number} score - 0 to 1
 * @returns {string} CSS color
 */
function riskColor(score) {
    if (score >= 0.8) return '#dc2626';  // Critical
    if (score >= 0.6) return '#ea580c';  // High
    if (score >= 0.4) return '#ca8a04';  // Medium
    if (score >= 0.2) return '#2563eb';  // Low
    return '#16a34a';                     // Healthy
}

function riskClass(score) {
    if (score >= 0.8) return 'risk-critical';
    if (score >= 0.6) return 'risk-high';
    if (score >= 0.4) return 'risk-medium';
    if (score >= 0.2) return 'risk-low';
    return 'risk-healthy';
}

/**
 * Format large numbers: 1234567 → "1.23M"
 */
function formatNumber(n) {
    if (n == null) return '0';
    if (n >= 1e6) return (n / 1e6).toFixed(2) + 'M';
    if (n >= 1e3) return (n / 1e3).toFixed(1) + 'K';
    return n.toLocaleString();
}

/**
 * Format bytes: 1234567 → "1.18 MB"
 */
function formatBytes(bytes) {
    if (!bytes) return '0 B';
    const units = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(1024));
    return (bytes / Math.pow(1024, i)).toFixed(i > 0 ? 1 : 0) + ' ' + units[i];
}

/**
 * Format nanosecond timestamp to locale string.
 */
function formatTimestamp(ns) {
    if (!ns) return '--';
    return new Date(ns / 1e6).toLocaleString();
}

/**
 * Relative time: "2m ago", "3h ago", "1d ago"
 */
function timeAgo(ns) {
    if (!ns) return '--';
    const diffMs = Date.now() - ns / 1e6;
    if (diffMs < 60000) return Math.floor(diffMs / 1000) + 's ago';
    if (diffMs < 3600000) return Math.floor(diffMs / 60000) + 'm ago';
    if (diffMs < 86400000) return Math.floor(diffMs / 3600000) + 'h ago';
    return Math.floor(diffMs / 86400000) + 'd ago';
}


// ── Chart.js dark theme defaults ───────────────────────────────────
if (typeof Chart !== 'undefined') {
    Chart.defaults.color = '#b4bcd0';
    Chart.defaults.borderColor = 'rgba(0,217,255,0.08)';
    Chart.defaults.font.family = "'Inter', 'Segoe UI', system-ui, -apple-system, sans-serif";
    Chart.defaults.font.size = 11;
    Chart.defaults.plugins.legend.labels.usePointStyle = true;
    Chart.defaults.plugins.legend.labels.pointStyleWidth = 8;
    Chart.defaults.plugins.tooltip.backgroundColor = 'rgba(10,14,39,0.95)';
    Chart.defaults.plugins.tooltip.borderColor = 'rgba(0,217,255,0.3)';
    Chart.defaults.plugins.tooltip.borderWidth = 1;
    Chart.defaults.plugins.tooltip.cornerRadius = 8;
    Chart.defaults.plugins.tooltip.padding = 10;
    Chart.defaults.elements.line.tension = 0.3;
    Chart.defaults.elements.point.radius = 0;
    Chart.defaults.elements.point.hoverRadius = 4;
    Chart.defaults.elements.bar.borderRadius = 4;
    Chart.defaults.animation.duration = 600;
    Chart.defaults.responsive = true;
    Chart.defaults.maintainAspectRatio = false;
}
