<?php
/**
 * AMOSKYS Aegis — POI Runtime Classifier (v0.7)
 *
 * Defensive pair to argos/ast/poi.py. The AST scanner catches
 * `unserialize($_POST...)` in plugin source; this sensor catches
 * the exploitation attempt at runtime by detecting serialized-PHP
 * payloads (specifically those containing an object marker) in
 * request input — regardless of which plugin's unserialize() they
 * target.
 *
 * How PHP serialization looks
 * ─────────────────────────────────────────────────────────────────
 * Serialized PHP uses a compact type-prefixed grammar:
 *
 *   N;                      - null
 *   b:0;  b:1;              - booleans
 *   i:42;                   - integer
 *   d:1.5;                  - double
 *   s:5:"hello";            - string (length-prefixed)
 *   a:N:{ ... }             - array
 *   O:<n>:"<ClassName>":<props>:{ ... }   ← OBJECT — POI gadget source
 *   C:<n>:"<ClassName>":<len>:{ ... }     ← Custom-serialized object
 *   r:<n>;  R:<n>;          - references
 *
 * The `O:` and `C:` markers are the dangerous ones — they cause PHP
 * to instantiate an object of the named class, triggering any
 * __wakeup / __destruct / __toString gadget that class declares.
 * No legitimate browser or client sends these in request input.
 *
 * What we detect
 * ─────────────────────────────────────────────────────────────────
 *   1. OBJECT_MARKER — the regex `O:\d+:"[A-Za-z_\\\\][\w\\\\]*":\d+:{`
 *      anywhere in a string value. This is the only reliable POI
 *      fingerprint; a legitimate application sending a serialized
 *      array (`a:...`) is rare enough but still possible, so we flag
 *      only objects.
 *
 *   2. CUSTOM_SERIALIZE_MARKER — the `C:` analog. Even rarer in legit
 *      traffic than `O:`.
 *
 *   3. NESTED_OBJECT_CHAIN — more than 3 `O:` markers in one payload.
 *      This is the fingerprint of an actual gadget chain (vs. a
 *      one-off object), so we emit at a separate severity tier.
 *
 * Scope
 * ─────────────────────────────────────────────────────────────────
 * We inspect (flattened):
 *   - $_GET, $_POST, $_COOKIE, $_REQUEST, $_SERVER['HTTP_X_*']
 *   - JSON and serialized-PHP request bodies (php://input) when the
 *     Content-Type suggests textual
 *   - The request path (URI-decoded) and query string
 *
 * We DO NOT inspect:
 *   - $_FILES content (handled by upload sensor v0.6)
 *   - Authorization headers (risk of logging credentials)
 *
 * Response ladder
 * ─────────────────────────────────────────────────────────────────
 *   Any hit → `aegis.request.poi_payload` at severity CRITICAL.
 *   Strike `poi_attempt` (threshold 1) → immediate 10-min block.
 *   Matches behavior of the v0.4 REST canary; this extends to the
 *   entire request surface, not just the canary route.
 *
 * Per-request budget
 * ─────────────────────────────────────────────────────────────────
 * We stop scanning after MAX_STRINGS_SCANNED = 200 string values per
 * request so an attacker can't OOM us with a 50-MB POST.
 *
 * @package AmoskysAegis
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Amoskys_Aegis_Poi_Sensor {

	/** @var Amoskys_Aegis_Emitter */
	private $emitter;

	const STRIKE_RULE = 'poi_attempt';
	const MAX_STRINGS_SCANNED = 200;
	const MAX_BODY_BYTES = 65536; // 64 KB of raw body scanning

	/** True after we've inspected this request. Prevents double-scan. */
	private $inspected = false;

	public function __construct( Amoskys_Aegis_Emitter $emitter ) {
		$this->emitter = $emitter;
	}

	public function register(): void {
		// `init` fires after WP has parsed $_GET/$_POST/$_COOKIE and has
		// populated the rewrite engine, but before any REST/admin-ajax
		// handler has run. Priority -100 so we beat every plugin that
		// might genuinely want to unserialize request data.
		add_action( 'init', array( $this, 'inspect_request' ), -100 );
	}

	public function inspect_request(): void {
		if ( $this->inspected ) {
			return;
		}
		$this->inspected = true;

		// DEBUG: prove the hook fires.
		$this->emitter->emit( 'aegis.request.poi_sensor_tick', array(
			'post_count' => isset( $_POST ) && is_array( $_POST ) ? count( $_POST ) : -1,
			'get_count'  => isset( $_GET )  && is_array( $_GET )  ? count( $_GET )  : -1,
		), 'info' );

		// Skip WP-CLI and cron — no HTTP request to scan.
		if ( ( defined( 'WP_CLI' ) && WP_CLI )
		  || ( defined( 'DOING_CRON' ) && DOING_CRON ) ) {
			return;
		}

		$scanned = 0;
		$hits = array();

		// Access the superglobals by name — auto_globals_jit means $GLOBALS
		// access may not materialize them. Touching $_GET etc. directly
		// forces PHP to initialize them.
		$sources = array(
			'_GET'     => isset( $_GET )     && is_array( $_GET )     ? $_GET     : null,
			'_POST'    => isset( $_POST )    && is_array( $_POST )    ? $_POST    : null,
			'_COOKIE'  => isset( $_COOKIE )  && is_array( $_COOKIE )  ? $_COOKIE  : null,
			'_REQUEST' => isset( $_REQUEST ) && is_array( $_REQUEST ) ? $_REQUEST : null,
		);
		foreach ( $sources as $name => $arr ) {
			if ( ! is_array( $arr ) ) {
				continue;
			}
			$scanned = $this->walk_recursive( $arr, $name, $scanned, $hits );
			if ( $scanned >= self::MAX_STRINGS_SCANNED ) {
				break;
			}
		}

		// Request path + query string (URL-decoded).
		if ( isset( $_SERVER['REQUEST_URI'] ) ) {
			$uri = urldecode( (string) $_SERVER['REQUEST_URI'] );
			$this->check_value( $uri, 'REQUEST_URI', $hits );
			$scanned++;
		}

		// Custom headers that commonly carry payloads (X-Forwarded-*, X-*).
		foreach ( $_SERVER as $k => $v ) {
			if ( is_string( $k ) && strpos( $k, 'HTTP_X_' ) === 0 && is_string( $v ) ) {
				$this->check_value( $v, $k, $hits );
				$scanned++;
				if ( $scanned >= self::MAX_STRINGS_SCANNED ) {
					break;
				}
			}
		}

		// Raw body — only for textual content types, and capped at 64 KB.
		$ctype = strtolower( isset( $_SERVER['CONTENT_TYPE'] ) ? (string) $_SERVER['CONTENT_TYPE'] : '' );
		if ( $ctype && ( strpos( $ctype, 'text' ) !== false
		              || strpos( $ctype, 'json' ) !== false
		              || strpos( $ctype, 'urlencoded' ) !== false
		              || strpos( $ctype, 'xml' ) !== false ) ) {
			$body = @file_get_contents( 'php://input', false, null, 0, self::MAX_BODY_BYTES );
			if ( is_string( $body ) && $body !== '' ) {
				$this->check_value( $body, 'REQUEST_BODY', $hits );
			}
		}

		if ( empty( $hits ) ) {
			return;
		}

		$ip = $this->get_ip();
		$top_sev = 'critical';

		$this->emitter->emit(
			'aegis.request.poi_payload',
			array(
				'ip'      => $ip,
				'hits'    => $hits,
				'hit_count' => count( $hits ),
				'classes' => array_values( array_unique( array_column( $hits, 'class' ) ) ),
			),
			$top_sev
		);

		// Always strike — any POI payload is worth blocking.
		if ( $ip ) {
			do_action( 'amoskys_aegis_strike', self::STRIKE_RULE, $ip );
		}
	}

	/**
	 * Walk a mixed array, pushing each string through check_value.
	 * Returns updated scanned-counter.
	 */
	private function walk_recursive( array $arr, string $path, int $scanned, array &$hits ): int {
		foreach ( $arr as $k => $v ) {
			if ( $scanned >= self::MAX_STRINGS_SCANNED ) {
				return $scanned;
			}
			$sub_path = $path . '[' . ( is_int( $k ) ? $k : (string) $k ) . ']';
			if ( is_array( $v ) ) {
				$scanned = $this->walk_recursive( $v, $sub_path, $scanned, $hits );
				continue;
			}
			if ( is_string( $v ) && $v !== '' ) {
				$this->check_value( $v, $sub_path, $hits );
				$scanned++;
			}
		}
		return $scanned;
	}

	/**
	 * Apply the POI regexes to one string value. Appends to $hits.
	 */
	private function check_value( string $value, string $location, array &$hits ): void {
		// Cheap pre-filter: both "O:" and "C:" at byte offset followed by
		// a digit. Skip on fast path if neither appears.
		if ( strpos( $value, 'O:' ) === false && strpos( $value, 'C:' ) === false ) {
			return;
		}

		$object_marker = '/O:\d+:"[\\\\A-Za-z_][\\\\\\w]*":\d+:\s*\{/';
		$custom_marker = '/C:\d+:"[\\\\A-Za-z_][\\\\\\w]*":\d+:\s*\{/';

		$o_count = preg_match_all( $object_marker, $value, $o_matches );
		$c_count = preg_match_all( $custom_marker, $value, $c_matches );

		if ( ! $o_count && ! $c_count ) {
			return;
		}

		// Class names we observed (first 3 per match type).
		$classes_seen = array();
		if ( $o_count ) {
			foreach ( array_slice( $o_matches[0], 0, 3 ) as $m ) {
				if ( preg_match( '/"([^"]+)"/', $m, $cn ) ) {
					$classes_seen[] = $cn[1];
				}
			}
		}
		if ( $c_count ) {
			foreach ( array_slice( $c_matches[0], 0, 3 ) as $m ) {
				if ( preg_match( '/"([^"]+)"/', $m, $cn ) ) {
					$classes_seen[] = $cn[1];
				}
			}
		}

		$class = 'OBJECT_MARKER';
		if ( ( $o_count + $c_count ) > 3 ) {
			$class = 'NESTED_OBJECT_CHAIN';
		} elseif ( $c_count ) {
			$class = 'CUSTOM_SERIALIZE_MARKER';
		}

		$hits[] = array(
			'location'     => $location,
			'class'        => $class,
			'object_count' => (int) $o_count,
			'custom_count' => (int) $c_count,
			'classes'      => array_values( array_unique( $classes_seen ) ),
			'snippet'      => substr( $value, 0, 300 ),
		);
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
