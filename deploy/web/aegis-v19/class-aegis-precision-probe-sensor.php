<?php
/**
 * AMOSKYS Aegis — Precision-Probe Meta Sensor (v1.9)
 *
 * Paired defense to argos/precision/. Our scanner_shape sensor is
 * tuned for COMMODITY scanners — it scores on path diversity, UA
 * rotation, timing uniformity, many-probes-per-minute. That is
 * exactly what an APT-grade attacker avoids.
 *
 * This sensor catches the OPPOSITE shape: ONE request, from a
 * previously-unseen IP, targeting a highly-specific parameter shape
 * that only an attacker who read the plugin's source code would
 * know to send.
 *
 * Detection logic
 * ───────────────
 * We flag a request when ALL of these are true:
 *
 *   (1) PATH_IS_PLUGIN_SPECIFIC  — the request targets
 *       /wp-admin/admin-ajax.php, /wp-admin/admin-post.php, or a
 *       plugin REST namespace (/wp-json/<slug>/v<N>/...).
 *
 *   (2) CONTAINS_EXPLOITATION_SHAPE — the query OR body carries a
 *       "probe signature": a SLEEP()/BENCHMARK()/WAITFOR payload, a
 *       serialized-object tag (O:<N>:"<class>":), an `<?php`/`<?=`
 *       content fragment in a multipart field, an `interact.sh`-
 *       or canary-shaped URL param, or a `..` path-traversal
 *       sequence in any value.
 *
 *   (3) SOURCE_IS_NEW — this IP has not visited any /wp-json/ or
 *       /wp-admin/ path in the last `NEW_IP_WINDOW_SEC` seconds
 *       (default 7 days). Normal users + returning customers fail
 *       this check and are ignored; a first-ever visitor going
 *       straight to a plugin-specific exploit vector is the shape
 *       we want to catch.
 *
 *   (4) NOT A SCANNER_SHAPE ALREADY — if aegis.scanner.shape_detected
 *       already fired for this IP in this window, we skip (that
 *       sensor handles commodity scanners; this one fills its blind
 *       spot).
 *
 * When all four hit, emit `aegis.attacker.precision_probe` at
 * severity CRITICAL and fire a strike `precision_probe` (threshold
 * 1 → instant 10-min block).
 *
 * Why this works
 * ──────────────
 * A commodity scanner sprays 800 probes: paths diverse, shapes
 * rotated, the scanner_shape meta-sensor catches it. An APT sends
 * ONE probe: no diversity, nothing to score on. But the probe
 * itself carries a signature a legitimate visitor would never
 * emit — a serialized PHP object, a SLEEP() payload, a canary URL.
 * This sensor fires on that single-request shape.
 *
 * @package AmoskysAegis
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Amoskys_Aegis_Precision_Probe_Sensor {

	/** @var Amoskys_Aegis_Emitter */
	private $emitter;

	const STRIKE_RULE       = 'precision_probe';
	const SEEN_IP_OPTION    = 'amoskys_aegis_seen_ips_v1';
	const NEW_IP_WINDOW_SEC = 604800;  // 7 days
	const SEEN_CAP          = 10000;    // bound the seen-IP set

	/**
	 * Exploitation-shape regexes.  Each identifies content that
	 * a legitimate visitor would never emit on a plugin-specific path.
	 */
	const SHAPE_REGEX_MAP = array(
		'TIME_BASED_SQLI'      => '/\b(SLEEP|BENCHMARK)\s*\(|\bWAITFOR\s+DELAY\b/i',
		'SERIALIZED_OBJECT'    => '/O:\d+:"[A-Za-z_\\\\][\w\\\\]*":\d+:\s*\{/',
		'PHP_OPEN_TAG'         => '/<\?php|<\?=/',
		'PATH_TRAVERSAL'       => '/(\.\.(\/|%2F)){2,}/i',
		'CANARY_DOMAIN'        => '/interact\.sh|canary\.|oast\.(pro|online|site)/i',
		'UNION_SELECT_SCHEMA'  => '/\bUNION\s+(ALL\s+)?SELECT\b.*\binformation_schema\b/is',
		'BASE64_EVAL'          => '/eval\s*\(\s*base64_decode/i',
	);

	public function __construct( Amoskys_Aegis_Emitter $emitter ) {
		$this->emitter = $emitter;
	}

	public function register(): void {
		// init @ -80 — after recon/scanner_shape/poi/csrf/ssrf/upload
		// sensors have had their chance to classify. This one is the
		// catch-all for the single-request exploitation pattern that
		// none of them trip on.
		add_action( 'init', array( $this, 'inspect_request' ), -80 );
	}

	public function inspect_request(): void {
		if ( ( defined( 'WP_CLI' ) && WP_CLI )
		  || ( defined( 'DOING_CRON' ) && DOING_CRON ) ) {
			return;
		}
		if ( function_exists( 'is_user_logged_in' ) && is_user_logged_in() ) {
			return;
		}

		$uri = isset( $_SERVER['REQUEST_URI'] ) ? (string) $_SERVER['REQUEST_URI'] : '';
		if ( $uri === '' ) return;
		$path = strtok( $uri, '?' );

		// (1) PATH_IS_PLUGIN_SPECIFIC
		$is_plugin_path = (
			$path === '/wp-admin/admin-ajax.php'
		 || $path === '/wp-admin/admin-post.php'
		 || preg_match( '#^/wp-json/(?!wp/|oembed/|wp-site-health/)[a-z0-9][-a-z0-9._]*/#i', $path )
		);
		if ( ! $is_plugin_path ) return;

		$ip = $this->get_ip();
		if ( ! $ip ) return;

		// (4) SKIP if scanner_shape has already EMITTED for this IP
		// (rec->emitted flag set to true). The bare transient is created
		// on every repeat-visitor request so its mere existence isn't a
		// "scanner_shape already fired" signal.
		$ss_rec = get_transient( 'amoskys_scanner_shape_' . md5( $ip ) );
		if ( is_array( $ss_rec ) && ! empty( $ss_rec['emitted'] ) ) {
			return;
		}

		// (2) CONTAINS_EXPLOITATION_SHAPE — scan GET + POST + body.
		$payload_blob = $this->collect_payload_blob();
		$matched_classes = array();
		foreach ( self::SHAPE_REGEX_MAP as $class => $regex ) {
			if ( @preg_match( $regex, $payload_blob ) ) {
				$matched_classes[] = $class;
			}
		}
		if ( empty( $matched_classes ) ) return;

		// (3) SOURCE_IS_NEW — never seen this IP on a plugin-path before.
		$seen = $this->load_seen_ips();
		$is_new = ! isset( $seen[ $ip ] );
		$this->mark_ip_seen( $ip, $seen );
		if ( ! $is_new ) {
			return;
		}

		// All four conditions met → emit + strike.
		$inbound_ua = isset( $_SERVER['HTTP_USER_AGENT'] ) ? (string) $_SERVER['HTTP_USER_AGENT'] : '';
		$this->emitter->emit(
			'aegis.attacker.precision_probe',
			array(
				'ip'              => $ip,
				'path'            => $path,
				'matched_classes' => $matched_classes,
				'ua'              => substr( $inbound_ua, 0, 150 ),
				'payload_excerpt' => substr( $payload_blob, 0, 300 ),
			),
			'critical'
		);
		do_action( 'amoskys_aegis_strike', self::STRIKE_RULE, $ip );
	}

	/**
	 * Concatenate all request input sources into one string for the
	 * single regex pass. We cap the body at 32 KB to protect FPM.
	 */
	private function collect_payload_blob(): string {
		$parts = array();
		// Request URI (decoded — so %2e%2e expansions get matched).
		if ( isset( $_SERVER['REQUEST_URI'] ) ) {
			$parts[] = urldecode( (string) $_SERVER['REQUEST_URI'] );
		}
		// GET + POST + COOKIE + REQUEST supers.
		foreach ( array( $_GET, $_POST, $_COOKIE, $_REQUEST ) as $super ) {
			if ( ! is_array( $super ) ) continue;
			foreach ( $super as $v ) {
				if ( is_string( $v ) && $v !== '' ) {
					$parts[] = wp_unslash( $v );
				} elseif ( is_array( $v ) ) {
					// One level of flattening is enough for common cases.
					foreach ( $v as $vv ) {
						if ( is_string( $vv ) ) {
							$parts[] = wp_unslash( $vv );
						}
					}
				}
			}
		}
		// Raw body (textual content types only).
		$ctype = strtolower( isset( $_SERVER['CONTENT_TYPE'] ) ? (string) $_SERVER['CONTENT_TYPE'] : '' );
		if ( $ctype && ( strpos( $ctype, 'text' ) !== false
		              || strpos( $ctype, 'json' ) !== false
		              || strpos( $ctype, 'urlencoded' ) !== false
		              || strpos( $ctype, 'xml' ) !== false
		              || strpos( $ctype, 'multipart' ) !== false ) ) {
			$body = @file_get_contents( 'php://input', false, null, 0, 32768 );
			if ( is_string( $body ) && $body !== '' ) {
				$parts[] = $body;
			}
		}
		return implode( "\n", $parts );
	}

	/** Load the seen-IPs map (bounded dict). */
	private function load_seen_ips(): array {
		$m = get_option( self::SEEN_IP_OPTION, array() );
		if ( ! is_array( $m ) ) $m = array();
		// Prune stale entries.
		$cutoff = time() - self::NEW_IP_WINDOW_SEC;
		foreach ( $m as $k => $ts ) {
			if ( (int) $ts < $cutoff ) unset( $m[ $k ] );
		}
		return $m;
	}

	/** Remember we've seen this IP (once, with TTL). */
	private function mark_ip_seen( string $ip, array $seen ): void {
		$seen[ $ip ] = time();
		// Cap size — evict oldest if over cap.
		if ( count( $seen ) > self::SEEN_CAP ) {
			asort( $seen );
			$seen = array_slice( $seen, -self::SEEN_CAP, null, true );
		}
		update_option( self::SEEN_IP_OPTION, $seen, false );
	}

	private function get_ip(): string {
		$trust_proxy = (bool) get_option( 'amoskys_aegis_trust_proxy', false );
		if ( $trust_proxy ) {
			foreach ( array( 'HTTP_CF_CONNECTING_IP', 'HTTP_X_FORWARDED_FOR', 'HTTP_X_REAL_IP' ) as $h ) {
				if ( ! empty( $_SERVER[ $h ] ) ) {
					$ip = trim( explode( ',', $_SERVER[ $h ] )[0] );
					if ( filter_var( $ip, FILTER_VALIDATE_IP ) ) {
						return $ip;
					}
				}
			}
		}
		return isset( $_SERVER['REMOTE_ADDR'] ) ? $_SERVER['REMOTE_ADDR'] : '';
	}
}
