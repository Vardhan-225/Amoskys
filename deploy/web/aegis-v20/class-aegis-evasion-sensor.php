<?php
/**
 * AMOSKYS Aegis — Evasion Detector (v2.0)
 *
 * Paired defense to argos/evasion/. Commodity scanners send clean
 * payloads that match well-known patterns; the scanner_shape and
 * db.suspicious_query sensors catch those. APT-grade attackers layer
 * encoding + mutation + case variation to defeat signature matching.
 *
 * This sensor normalizes the request (decoding cascades, stripping
 * comments, collapsing whitespace, case-folding) and THEN runs the
 * match. It also fires when it observes the SHAPE of evasion — e.g.
 * a request whose raw form contains `%2527` (double-URL-encoded
 * apostrophe) is a near-certain WAF-bypass attempt regardless of
 * what the payload is.
 *
 * Detection classes
 * ─────────────────
 *  DOUBLE_URL_ENCODED       — `%25xx%25xx` cascades
 *  UTF8_OVERLONG            — `%c0%ae`, `%c0%a7` sequences (overlong
 *                              single-byte chars)
 *  UNICODE_ESCAPE           — `%uXXXX` per-char unicode
 *  MYSQL_CONDITIONAL_COMMENT — `/*!50000...*\/` for SQL bypass
 *  COMMENT_OBFUSCATED_KEYWORD — `SEL/ **\ / ECT` pattern
 *  CASE_MIXED_KEYWORD        — `SeLeCt`, `uNiOn` — obvious attempt
 *                              to defeat keyword matchers
 *  NULL_BYTE_INJECTION      — `%00.` — PHP file-truncation trick
 *  HEX_ESCAPE_IN_QUERY      — `\xNN` escape in query params
 *  ENTITY_ENCODED_SCRIPT    — `&#60;script&#62;` HTML-entity XSS
 *  NORMALIZED_ATTACK_MATCH  — after decoding cascade, pattern matches
 *                              SQLi/XSS/LFI/RCE signature
 *
 * Any hit → emit `aegis.evasion.detected` at severity CRITICAL
 * and fire strike `evasion_attempt` (threshold 1 → instant block).
 *
 * @package AmoskysAegis
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Amoskys_Aegis_Evasion_Sensor {

	/** @var Amoskys_Aegis_Emitter */
	private $emitter;

	const STRIKE_RULE = 'evasion_attempt';

	/** Raw-form patterns — no decoding needed, these ARE the evasion signature. */
	const RAW_PATTERNS = array(
		'DOUBLE_URL_ENCODED'        => '/%25[0-9a-fA-F]{2}/',
		'UTF8_OVERLONG'             => '/%c0%[a-fA-F0-9]{2}|%c1%[a-fA-F0-9]{2}/i',
		'UNICODE_ESCAPE'            => '/%u[0-9a-fA-F]{4}/',
		'MYSQL_CONDITIONAL_COMMENT' => '/\/\*!\d*[A-Z_]+/i',
		'NULL_BYTE_INJECTION'       => '/%00\./',
		'HEX_ESCAPE_IN_QUERY'       => '/\\\\x[0-9a-fA-F]{2}/',
		'ENTITY_ENCODED_SCRIPT'     => '/&#(x3[cC]|60);\s*s\s*c\s*r\s*i\s*p\s*t/i',
	);

	/**
	 * Mixed-case SQL keyword pattern. We require AT LEAST 3 alpha chars
	 * in the keyword and mixed case (not all-upper, not all-lower).
	 * SeLeCt matches; SELECT or select do NOT.
	 */
	const MIXED_CASE_KEYWORDS = array(
		'SELECT', 'UNION', 'INSERT', 'UPDATE', 'DELETE', 'WHERE', 'FROM',
		'SCRIPT', 'ALERT', 'ONERROR', 'ONLOAD', 'JAVASCRIPT',
	);

	/**
	 * Attack pattern matcher — run AFTER the decoding cascade. If a
	 * request decoded once URL-encoded + case-folded contains these
	 * patterns AND the raw form did NOT, it's evasion.
	 */
	const NORMALIZED_ATTACK_PATTERNS = array(
		'SQLi'  => '/\b(union\s+(all\s+)?select|or\s+1=1|and\s+sleep\s*\(|waitfor\s+delay)\b/i',
		'XSS'   => '/<script\b|javascript:\s*alert|onerror\s*=/i',
		'LFI'   => '/\.\.[\\\\\/]|\/etc\/passwd|php:\/\/filter/i',
		'RCE'   => '/;\s*(id|sleep|cat|nc|wget)\b|\$\(.*\)|`.*`/i',
	);

	public function __construct( Amoskys_Aegis_Emitter $emitter ) {
		$this->emitter = $emitter;
	}

	public function register(): void {
		// Double-hook: init @ -75 catches most requests, plugins_loaded @
		// 10 catches the edge cases (invalid-UTF-8 URIs that WordPress
		// itself aborts before firing init). We use an instance-level
		// inspected-flag to ensure we only fire once per request.
		add_action( 'plugins_loaded', array( $this, 'inspect_request' ), 10 );
		add_action( 'init', array( $this, 'inspect_request' ), -75 );
	}

	/** Guard so we don't double-emit when both hooks run. */
	private $inspected = false;

	public function inspect_request(): void {
		if ( $this->inspected ) return;   // one-shot per request
		$this->inspected = true;

		if ( ( defined( 'WP_CLI' ) && WP_CLI )
		  || ( defined( 'DOING_CRON' ) && DOING_CRON ) ) {
			return;
		}
		if ( function_exists( 'is_user_logged_in' ) && is_user_logged_in() ) {
			return;
		}
		$uri = isset( $_SERVER['REQUEST_URI'] ) ? (string) $_SERVER['REQUEST_URI'] : '';
		if ( $uri === '' ) return;

		$raw_blob = $this->collect_raw_blob();
		if ( $raw_blob === '' ) return;

		$matched_classes = array();

		// 1. Raw-form evasion signatures.
		foreach ( self::RAW_PATTERNS as $class => $regex ) {
			if ( @preg_match( $regex, $raw_blob ) ) {
				$matched_classes[] = $class;
			}
		}

		// 2. Mixed-case keyword (suspicious case shuffling for keyword-list WAFs).
		if ( $this->contains_mixed_case_keyword( $raw_blob ) ) {
			$matched_classes[] = 'CASE_MIXED_KEYWORD';
		}

		// 3. Comment-obfuscated keywords: SEL/**/ECT, UN/**/ION.
		if ( preg_match( '/\b[a-z]{2,}\/\*.*?\*\/[a-z]{2,}/i', $raw_blob ) ) {
			$matched_classes[] = 'COMMENT_OBFUSCATED_KEYWORD';
		}

		// 4. Normalized attack matcher — decode URL once + case-fold,
		// then check. If the pattern matches AFTER normalization but
		// NOT in the raw form, the attacker deliberately obfuscated.
		$normalized = $this->normalize( $raw_blob );
		foreach ( self::NORMALIZED_ATTACK_PATTERNS as $class => $regex ) {
			if ( @preg_match( $regex, $normalized )
			  && ! @preg_match( $regex, $raw_blob ) ) {
				$matched_classes[] = 'NORMALIZED_' . $class;
			}
		}

		if ( empty( $matched_classes ) ) return;

		$ip = $this->get_ip();
		if ( ! $ip ) return;

		$this->emitter->emit(
			'aegis.evasion.detected',
			array(
				'ip'              => $ip,
				'matched_classes' => array_values( array_unique( $matched_classes ) ),
				'path'            => strtok( $uri, '?' ),
				'raw_excerpt'     => substr( $raw_blob, 0, 200 ),
				'normalized_excerpt' => substr( $normalized, 0, 200 ),
			),
			'critical'
		);
		do_action( 'amoskys_aegis_strike', self::STRIKE_RULE, $ip );
	}

	/**
	 * Concatenate raw (NOT decoded) input surfaces.
	 */
	private function collect_raw_blob(): string {
		$parts = array();
		// Use the RAW request URI (PHP gives it URL-encoded for us).
		if ( isset( $_SERVER['REQUEST_URI'] ) ) {
			$parts[] = (string) $_SERVER['REQUEST_URI'];
		}
		// $_GET/$_POST are already URL-decoded by PHP. To see the RAW
		// form we'd need QUERY_STRING + php://input.
		if ( isset( $_SERVER['QUERY_STRING'] ) ) {
			$parts[] = (string) $_SERVER['QUERY_STRING'];
		}
		// Raw body (textual only, bounded).
		$ctype = strtolower( isset( $_SERVER['CONTENT_TYPE'] ) ? (string) $_SERVER['CONTENT_TYPE'] : '' );
		if ( $ctype && ( strpos( $ctype, 'text' ) !== false
		              || strpos( $ctype, 'json' ) !== false
		              || strpos( $ctype, 'urlencoded' ) !== false
		              || strpos( $ctype, 'xml' ) !== false ) ) {
			$body = @file_get_contents( 'php://input', false, null, 0, 32768 );
			if ( is_string( $body ) && $body !== '' ) {
				$parts[] = $body;
			}
		}
		// Cookies (can carry encoded payloads too).
		if ( isset( $_SERVER['HTTP_COOKIE'] ) ) {
			$parts[] = (string) $_SERVER['HTTP_COOKIE'];
		}
		return implode( "\n", $parts );
	}

	/**
	 * URL-decode once + case-fold for the normalized-attack-match pass.
	 */
	private function normalize( string $s ): string {
		$decoded = urldecode( $s );
		// Also collapse /* ... */ comments so SEL/**/ECT -> SELECT.
		$decoded = preg_replace( '/\/\*.*?\*\//s', '', $decoded );
		// Collapse redundant whitespace.
		$decoded = preg_replace( '/\s+/', ' ', $decoded );
		return $decoded;
	}

	/**
	 * Return true if $s contains a mixed-case variant of any keyword
	 * in MIXED_CASE_KEYWORDS (e.g., "SeLeCt", "uNiOn").
	 */
	private function contains_mixed_case_keyword( string $s ): bool {
		foreach ( self::MIXED_CASE_KEYWORDS as $kw ) {
			// Case-insensitive search; then check the matched substring
			// is mixed-case (neither all-upper nor all-lower).
			$pattern = '/\b' . preg_quote( $kw, '/' ) . '\b/i';
			if ( preg_match_all( $pattern, $s, $matches ) ) {
				foreach ( $matches[0] as $hit ) {
					$upper = strtoupper( $hit );
					$lower = strtolower( $hit );
					if ( $hit !== $upper && $hit !== $lower ) {
						return true;
					}
				}
			}
		}
		return false;
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
