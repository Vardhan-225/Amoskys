<?php
/**
 * AMOSKYS Aegis — Active Defense (Block Engine)
 *
 * The first blocking feature. Takes the observation stream from the
 * existing sensors and turns specific burst patterns into 403
 * responses.
 *
 * Design principles
 * ─────────────────────────────────────────────────────────────────
 *   1. Fail-open — if the block engine throws, a real user request
 *      is never broken. We'd rather miss a block than brick a site.
 *   2. Stateful via WordPress transients (auto-expire, no schema).
 *   3. Enforcement runs at `plugins_loaded` priority -1 so we beat
 *      every other plugin in the request lifecycle.
 *   4. Every block emits `aegis.block.enforced` — the fact that we
 *      blocked is itself a first-class event.
 *   5. Bypass hatch for the admin's own IP (if known) via a whitelist
 *      option that a legit admin can set from wp-admin.
 *
 * Rules (v0.1) — configurable at the top of the class:
 *   NONCE_FAIL_BURST    — more than 10 nonce fails in 60s from one IP
 *   PRIV_ESC_BURST      — more than 3 capability-denied in 60s
 *   SCANNER_404_BURST   — more than 5 suspicious 404s in 60s
 *   AUTH_FAIL_BURST     — more than 8 login failures in 60s
 *   POI_ATTEMPT         — ANY PHP-Object-Injection canary → instant
 *                         permanent IP block (within TTL window)
 *
 * Block duration is 10 minutes by default. The block TTL is kept
 * deliberately short — we're protecting a WordPress site, not
 * running a jail. Persistent IPs eventually get logged for the
 * brain to re-classify.
 *
 * @package AmoskysAegis
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Amoskys_Aegis_Block {

	/** @var Amoskys_Aegis_Emitter */
	private $emitter;

	// ─────────────────────────────────────────────────────────────
	// Rule thresholds (events-in-window → block)
	// ─────────────────────────────────────────────────────────────

	const WINDOW_SECONDS      = 60;
	const BLOCK_DURATION_SEC  = 600; // 10 minutes

	const NONCE_FAIL_BURST    = 10;
	const PRIV_ESC_BURST      = 3;
	const SCANNER_404_BURST   = 5;
	const AUTH_FAIL_BURST     = 8;
	const POI_ATTEMPT_LIMIT   = 1; // one POI canary = immediate block

	// HTTP status used when blocking. 403 is correct but slightly noisy;
	// some operators prefer to return 444 (Nginx-style silent close).
	const BLOCK_HTTP_STATUS   = 403;

	public function __construct( Amoskys_Aegis_Emitter $emitter ) {
		$this->emitter = $emitter;
	}

	/**
	 * Wire the block engine into WordPress hooks.
	 *
	 * IMPORTANT: the main plugin calls `enforce()` DIRECTLY from its own
	 * `plugins_loaded @ -1` callback — not via `add_action` inside this
	 * register() method, because register() itself runs at that priority
	 * and any add_action() it makes is too late to fire this request.
	 *
	 * This method only wires the strike listener, which fires mid-request
	 * from sensor hooks and can be registered any time before they fire.
	 */
	public function register(): void {
		add_action( 'amoskys_aegis_strike', array( $this, 'count_strike' ), 10, 2 );
	}

	// ─────────────────────────────────────────────────────────────
	// ENFORCEMENT — called at plugins_loaded @ -1
	// ─────────────────────────────────────────────────────────────

	public function enforce(): void {
		// Only enforce on actual HTTP requests (not WP-CLI, not cron)
		if ( ( defined( 'WP_CLI' ) && WP_CLI ) || ( defined( 'DOING_CRON' ) && DOING_CRON ) ) {
			return;
		}

		$ip = $this->get_client_ip();
		if ( ! $ip ) {
			return;
		}
		if ( $this->is_whitelisted( $ip ) ) {
			return;
		}

		$entry = get_transient( 'amoskys_block_' . md5( $ip ) );
		if ( ! is_array( $entry ) || empty( $entry['blocked'] ) ) {
			return;
		}

		// We are blocking this request. Emit + 403 + die.
		$this->emitter->emit(
			'aegis.block.enforced',
			array(
				'ip'              => $ip,
				'rule'            => $entry['rule'] ?? 'unknown',
				'blocked_since'   => $entry['blocked_since'] ?? 0,
				'strike_count'    => $entry['strikes'] ?? 0,
				'request_uri'     => isset( $_SERVER['REQUEST_URI'] ) ? substr( $_SERVER['REQUEST_URI'], 0, 200 ) : null,
			),
			'warn'
		);

		status_header( self::BLOCK_HTTP_STATUS );
		nocache_headers();
		header( 'Content-Type: text/plain; charset=UTF-8' );
		echo "Access denied by AMOSKYS Aegis.\n";
		echo "If this is a mistake, contact the site owner.\n";
		exit;
	}

	// ─────────────────────────────────────────────────────────────
	// STRIKE TRACKING — sensors call this when their burst-worthy
	// variant fires. Thresholds trip → IP goes on the blocklist.
	// ─────────────────────────────────────────────────────────────

	/**
	 * @param string $rule    One of: nonce_fail | priv_esc | scanner_404 | auth_fail | poi_attempt
	 * @param string $ip      Originating IP (from sensor's own IP resolution)
	 */
	public function count_strike( string $rule, string $ip ): void {
		if ( ! $ip || $this->is_whitelisted( $ip ) ) {
			return;
		}

		// If this IP is already blocked, skip strike accounting entirely —
		// no point re-counting, no risk of spamming `block.started`.
		if ( get_transient( 'amoskys_block_' . md5( $ip ) ) ) {
			return;
		}

		$key = 'amoskys_strike_' . $rule . '_' . md5( $ip );
		$count = (int) get_transient( $key );
		$count++;
		set_transient( $key, $count, self::WINDOW_SECONDS );

		$threshold = $this->threshold_for( $rule );
		if ( $threshold <= 0 ) {
			return;
		}
		if ( $count < $threshold ) {
			return;
		}

		// Threshold met → block (block_ip itself is dedup-safe).
		$this->block_ip( $ip, $rule, $count );
	}

	private function threshold_for( string $rule ): int {
		switch ( $rule ) {
			case 'nonce_fail':  return self::NONCE_FAIL_BURST;
			case 'priv_esc':    return self::PRIV_ESC_BURST;
			case 'scanner_404': return self::SCANNER_404_BURST;
			case 'auth_fail':   return self::AUTH_FAIL_BURST;
			case 'poi_attempt': return self::POI_ATTEMPT_LIMIT;
			default: return 0;
		}
	}

	private function block_ip( string $ip, string $rule, int $strikes ): void {
		$block_key = 'amoskys_block_' . md5( $ip );

		// Already-blocked → refresh TTL, do NOT emit a second `block.started`.
		// (count_strike() short-circuits earlier, but this is a belt-and-braces
		// guarantee in case a different code path calls block_ip directly.)
		$existing = get_transient( $block_key );
		if ( is_array( $existing ) && ! empty( $existing['blocked'] ) ) {
			return;
		}

		$entry = array(
			'blocked'       => true,
			'rule'          => $rule,
			'blocked_since' => time(),
			'strikes'       => $strikes,
		);
		set_transient( $block_key, $entry, self::BLOCK_DURATION_SEC );

		// Emit the transition-to-blocked as a 'high' severity event
		// (the subsequent enforcement events are 'warn').
		$this->emitter->emit(
			'aegis.block.started',
			array(
				'ip'       => $ip,
				'rule'     => $rule,
				'strikes'  => $strikes,
				'ttl_sec'  => self::BLOCK_DURATION_SEC,
			),
			'high'
		);
	}

	// ─────────────────────────────────────────────────────────────
	// Whitelist — admins who've proven themselves recently don't
	// get caught in a rule they themselves tripped.
	// ─────────────────────────────────────────────────────────────

	private function is_whitelisted( string $ip ): bool {
		// 1. Loopback / link-local — WP-Cron often hits us as 127.0.0.1 or the
		//    server's own public IP via wp_remote_post. Never block self-traffic.
		if ( in_array( $ip, array( '127.0.0.1', '::1' ), true ) ) {
			return true;
		}
		$server_ip = isset( $_SERVER['SERVER_ADDR'] ) ? $_SERVER['SERVER_ADDR'] : '';
		if ( $server_ip && $ip === $server_ip ) {
			return true;
		}

		// 2. Admin-configured static whitelist.
		$wl = get_option( 'amoskys_aegis_ip_whitelist', '' );
		if ( $wl ) {
			foreach ( array_map( 'trim', explode( ',', $wl ) ) as $entry ) {
				if ( $entry && $ip === $entry ) {
					return true;
				}
			}
		}

		// 3. Last logged-in admin's own IP.
		$last_admin_ip = get_option( 'amoskys_aegis_last_admin_ip', '' );
		if ( $last_admin_ip && $ip === $last_admin_ip ) {
			return true;
		}

		// 4. Verified search-engine crawlers (forward-confirmed reverse DNS).
		//    We DON'T blindly trust UA — we reverse-resolve the IP and forward-
		//    verify the name. Cached for 24h per IP. Blocking Googlebot/Bingbot
		//    would be a catastrophic SEO footgun for our customers.
		if ( $this->is_verified_crawler( $ip ) ) {
			return true;
		}

		return false;
	}

	/**
	 * Forward-confirmed reverse DNS check: is $ip a legit Googlebot / Bingbot /
	 * DuckDuckBot / YandexBot / Baiduspider? Memoized for 24h in wp_options.
	 */
	private function is_verified_crawler( string $ip ): bool {
		$cache_key = 'amoskys_crawler_' . md5( $ip );
		$cached = get_transient( $cache_key );
		if ( $cached === 'yes' ) { return true; }
		if ( $cached === 'no'  ) { return false; }

		$host = @gethostbyaddr( $ip );
		if ( ! $host || $host === $ip ) {
			set_transient( $cache_key, 'no', DAY_IN_SECONDS );
			return false;
		}
		$host_lc = strtolower( $host );
		$allowed_suffixes = array(
			'.googlebot.com',
			'.google.com',
			'.search.msn.com',
			'.duckduckgo.com',
			'.yandex.ru', '.yandex.net', '.yandex.com',
			'.crawl.baidu.com',
		);
		$suffix_match = false;
		foreach ( $allowed_suffixes as $s ) {
			if ( substr( $host_lc, -strlen( $s ) ) === $s ) {
				$suffix_match = true; break;
			}
		}
		if ( ! $suffix_match ) {
			set_transient( $cache_key, 'no', DAY_IN_SECONDS );
			return false;
		}

		// Forward-verify: name must resolve back to this IP.
		$forward_ips = @gethostbynamel( $host );
		$ok = is_array( $forward_ips ) && in_array( $ip, $forward_ips, true );
		set_transient( $cache_key, $ok ? 'yes' : 'no', DAY_IN_SECONDS );
		return $ok;
	}

	/**
	 * Called by the auth sensor on successful admin login — records
	 * the admin's own IP so they don't get auto-blocked by a rule
	 * they themselves trip later (e.g., too many refreshes).
	 */
	public static function remember_admin_ip( string $ip ): void {
		if ( $ip && ! in_array( $ip, array( '127.0.0.1', '::1' ), true ) ) {
			update_option( 'amoskys_aegis_last_admin_ip', $ip, false );
		}
	}

	// ─────────────────────────────────────────────────────────────
	// Status introspection — used by the Command Center
	// ─────────────────────────────────────────────────────────────

	/**
	 * Return stats for the currently-blocked IP set.
	 * Walks the options table looking for amoskys_block_* transients.
	 */
	public static function current_blocks(): array {
		global $wpdb;
		$rows = $wpdb->get_col(
			"SELECT option_name FROM {$wpdb->options} WHERE option_name LIKE '_transient_amoskys_block_%'"
		);
		$blocks = array();
		foreach ( (array) $rows as $name ) {
			$key = str_replace( '_transient_', '', $name );
			$entry = get_transient( $key );
			if ( is_array( $entry ) && ! empty( $entry['blocked'] ) ) {
				$blocks[] = $entry;
			}
		}
		return $blocks;
	}

	// ─────────────────────────────────────────────────────────────
	// IP extraction (duplicate of the emitter logic — kept here so
	// the block engine never has to dereference the emitter)
	// ─────────────────────────────────────────────────────────────

	private function get_client_ip(): ?string {
		$trust_proxy = (bool) get_option( 'amoskys_aegis_trust_proxy', false );
		if ( $trust_proxy ) {
			foreach ( array( 'HTTP_CF_CONNECTING_IP', 'HTTP_X_FORWARDED_FOR', 'HTTP_X_REAL_IP' ) as $h ) {
				if ( ! empty( $_SERVER[ $h ] ) ) {
					$ip = explode( ',', $_SERVER[ $h ] )[0];
					$ip = trim( $ip );
					if ( filter_var( $ip, FILTER_VALIDATE_IP ) ) {
						return $ip;
					}
				}
			}
		}
		return isset( $_SERVER['REMOTE_ADDR'] ) ? $_SERVER['REMOTE_ADDR'] : null;
	}
}
