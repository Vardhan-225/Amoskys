<?php
/**
 * AMOSKYS Aegis — CSRF Runtime Classifier (v0.8)
 *
 * Defensive pair to argos/ast/csrf.py. The AST scanner catches
 * handlers missing a nonce check in source; this sensor catches
 * the attempted exploitation at runtime by watching for the request
 * shapes that suggest a CSRF attack.
 *
 * Detection strategy
 * ─────────────────────────────────────────────────────────────────
 * CSRF at runtime is hard to detect perfectly — we don't know which
 * POST endpoints on a given WP site "should have" a nonce. But we
 * can flag three high-signal patterns:
 *
 *   1. MISSING_REFERER
 *      A POST to wp-admin/admin-post.php, wp-admin/admin-ajax.php,
 *      or wp-login.php with NO Referer header at all. Legit browser
 *      traffic to those paths always carries a Referer. No referer
 *      = scripted or cross-origin attempt.
 *
 *   2. CROSS_ORIGIN_REFERER
 *      A POST to admin-post / admin-ajax / wp-login whose Referer's
 *      host doesn't match the site's host. Classic CSRF fingerprint.
 *      (Real third-party integrations exist; operator can whitelist.)
 *
 *   3. NONCE_FIELD_ABSENT
 *      POST to admin-post.php or admin-ajax.php with no `_wpnonce`,
 *      `_ajax_nonce`, or `nonce` parameter in either $_POST or $_GET.
 *      The vast majority of legit admin-ajax actions send one of
 *      these. Absence is a strong signal.
 *
 * Response
 * ─────────────────────────────────────────────────────────────────
 * All three emit `aegis.csrf.suspicious_request` at severity `high`.
 * On MISSING_REFERER to admin-post / wp-login (the highest-signal
 * case), we ALSO fire the strike `csrf_attempt` for a threshold
 * of 3/60s → 10-min block. Lower thresholds than the other sensors
 * because CSRF probes are usually single-shot.
 *
 * We DO NOT block the request itself — the existing nonce.failed
 * sensor from v0.3 already sees WordPress's own rejection, and we
 * don't want to double-enforce. This sensor is about capturing the
 * ATTEMPT pattern so the operator can see campaigns.
 *
 * @package AmoskysAegis
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Amoskys_Aegis_Csrf_Sensor {

	/** @var Amoskys_Aegis_Emitter */
	private $emitter;

	const STRIKE_RULE = 'csrf_attempt';

	/** Paths we watch. */
	const WATCHED_PATHS = array(
		'/wp-admin/admin-post.php',
		'/wp-admin/admin-ajax.php',
		'/wp-login.php',
	);

	/** True after we've inspected this request. */
	private $inspected = false;

	public function __construct( Amoskys_Aegis_Emitter $emitter ) {
		$this->emitter = $emitter;
	}

	public function register(): void {
		// init @ -95 runs just after the POI sensor at -100, before any
		// plugin/admin dispatch handler.
		add_action( 'init', array( $this, 'inspect_request' ), -95 );
	}

	public function inspect_request(): void {
		if ( $this->inspected ) {
			return;
		}
		$this->inspected = true;

		// Skip non-HTTP execution.
		if ( ( defined( 'WP_CLI' ) && WP_CLI )
		  || ( defined( 'DOING_CRON' ) && DOING_CRON ) ) {
			return;
		}
		$method = isset( $_SERVER['REQUEST_METHOD'] ) ? strtoupper( (string) $_SERVER['REQUEST_METHOD'] ) : 'GET';
		if ( $method !== 'POST' ) {
			return;
		}
		$uri = isset( $_SERVER['REQUEST_URI'] ) ? (string) $_SERVER['REQUEST_URI'] : '';
		$path = strtok( $uri, '?' );

		$is_watched = false;
		foreach ( self::WATCHED_PATHS as $w ) {
			if ( $path === $w || substr( $path, -strlen( $w ) ) === $w ) {
				$is_watched = true;
				break;
			}
		}
		if ( ! $is_watched ) {
			return;
		}

		$site_host = wp_parse_url( home_url( '/' ), PHP_URL_HOST );
		$referer = isset( $_SERVER['HTTP_REFERER'] ) ? (string) $_SERVER['HTTP_REFERER'] : '';
		$ip = $this->get_ip();
		$ua = isset( $_SERVER['HTTP_USER_AGENT'] ) ? (string) $_SERVER['HTTP_USER_AGENT'] : '';

		$classes = array();
		$detail = array();

		// 1. MISSING_REFERER
		if ( $referer === '' ) {
			$classes[] = 'MISSING_REFERER';
		} else {
			// 2. CROSS_ORIGIN_REFERER
			$ref_host = wp_parse_url( $referer, PHP_URL_HOST );
			if ( $ref_host && $site_host && strcasecmp( $ref_host, $site_host ) !== 0 ) {
				$classes[] = 'CROSS_ORIGIN_REFERER';
				$detail['referer_host'] = $ref_host;
				$detail['site_host']    = $site_host;
			}
		}

		// 3. NONCE_FIELD_ABSENT
		$has_nonce_field = false;
		foreach ( array( '_wpnonce', '_ajax_nonce', 'nonce' ) as $n ) {
			if ( ( isset( $_POST[ $n ] ) && $_POST[ $n ] !== '' )
			  || ( isset( $_GET[ $n ] )  && $_GET[ $n ]  !== '' ) ) {
				$has_nonce_field = true;
				break;
			}
		}
		// admin-ajax.php without ANY action parameter is too benign to flag
		// as CSRF (some plugins handle no-action health checks).
		$action = isset( $_POST['action'] ) ? sanitize_key( (string) $_POST['action'] )
		       : ( isset( $_GET['action'] )  ? sanitize_key( (string) $_GET['action'] )  : '' );

		if ( ! $has_nonce_field && $path !== '/wp-login.php' && $action !== '' ) {
			$classes[] = 'NONCE_FIELD_ABSENT';
			$detail['action'] = $action;
		}

		if ( empty( $classes ) ) {
			return;
		}

		$top_sev = 'high';
		if ( in_array( 'CROSS_ORIGIN_REFERER', $classes, true )
		  || ( in_array( 'MISSING_REFERER', $classes, true ) && $path !== '/wp-login.php' ) ) {
			$top_sev = 'high';
		}

		$this->emitter->emit(
			'aegis.csrf.suspicious_request',
			array(
				'ip'      => $ip,
				'path'    => $path,
				'classes' => $classes,
				'referer' => $referer ? substr( $referer, 0, 200 ) : null,
				'action'  => $action,
				'ua'      => substr( $ua, 0, 120 ),
				'detail'  => $detail,
			),
			$top_sev
		);

		// Strike only on MISSING_REFERER against admin-post/admin-ajax;
		// wp-login MISSING_REFERER is super noisy from scanners.
		if ( in_array( 'MISSING_REFERER', $classes, true )
		  && $path !== '/wp-login.php'
		  && $ip ) {
			do_action( 'amoskys_aegis_strike', self::STRIKE_RULE, $ip );
		}
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
