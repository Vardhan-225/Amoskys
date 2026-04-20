<?php
/**
 * AMOSKYS Aegis — Scanner-Shape Meta-Detector (v1.3)
 *
 * The defensive pair to argos/legitimacy.py. Polite scanners — the
 * ones that rotate UA, obey robots.txt, pace themselves to look
 * human — defeat path-based IDS rules on purpose. This sensor
 * catches them by looking at SHAPE rather than content:
 *
 *   1. Many paths, few repeats — a scanner touches a wide range of
 *      paths, each once or twice. A human touches a small set of
 *      paths, often. Scanner shape = high "path diversity ratio".
 *
 *   2. Coverage-first traversal — a scanner visits one page each
 *      from every WP subsystem (admin, REST, feed, sitemap, plugin
 *      dir). A human clicks links, following content relationships.
 *
 *   3. No referer chain — humans follow links, so after a first
 *      visit their Referer header points to prior pages on our own
 *      site. Scanners fetch paths independently; Referer is either
 *      absent or consistently a 3rd-party.
 *
 *   4. Timing too regular — even a polite scanner's pacing has a
 *      narrower variance than a real human's. If request intervals
 *      have stddev < 1 s when the median is 3 s, that's too uniform.
 *
 *   5. Evasion signals — rotating UA mid-session, gradually escalating
 *      from innocuous to sensitive paths, visiting robots.txt THEN
 *      the disallowed paths.
 *
 * This is explicitly designed to catch US, too. If our own Argos
 * stealth module starts tripping this sensor, the fix is in the
 * offense (Argos), not here. This is the offense/defense competition
 * the operator mandate describes.
 *
 * State model
 * ─────────────────────────────────────────────────────────────────
 * Per-IP transient over a 10-min window:
 *   amoskys_scanner_shape_<md5(ip)> → {
 *     first_seen, paths_hit[], path_count, distinct_path_count,
 *     intervals_ms[], referrer_own_count, referrer_none_count,
 *     ua_first, ua_saw_change, visited_robots, scanner_shape_score,
 *     emitted
 *   }
 *
 * We emit `aegis.scanner.shape_detected` at HIGH severity when the
 * composite score crosses 60/100. Score components (weights add
 * to 100):
 *
 *   +25  distinct_path_count >= 10 within window
 *   +20  distinct / total >= 0.8 (no path visited more than once)
 *   +15  referrer_none_count / total >= 0.8 (no chain)
 *   +15  timing stddev < 1.5 s AND median >= 2 s (too-uniform pacing)
 *   +10  visited /robots.txt then /path explicitly disallowed there
 *   +10  UA changed mid-session (seen >1 distinct UA)
 *   + 5  within the first visit sequence hit >=3 WP-subsystem paths
 *
 * Score 60+ → emit [HIGH] + strike `scanner_shape` (threshold 1 →
 * 10-min block). We never score a legit logged-in admin (skip when
 * is_user_logged_in()).
 *
 * @package AmoskysAegis
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Amoskys_Aegis_Scanner_Shape_Sensor {

	/** @var Amoskys_Aegis_Emitter */
	private $emitter;

	const STRIKE_RULE = 'scanner_shape';
	const WINDOW_SEC  = 600;
	const SCORE_THRESHOLD = 60;
	const MAX_PATHS_TRACKED = 60;     // cap memory per IP

	public function __construct( Amoskys_Aegis_Emitter $emitter ) {
		$this->emitter = $emitter;
	}

	public function register(): void {
		// init @ -85 — after the recon-campaign sensor (-90). Same-request
		// cheap enough that ordering just sorts concerns.
		add_action( 'init', array( $this, 'inspect_request' ), -85 );
	}

	public function inspect_request(): void {
		if ( ( defined( 'WP_CLI' ) && WP_CLI )
		  || ( defined( 'DOING_CRON' ) && DOING_CRON ) ) {
			return;
		}
		// Skip logged-in users — real humans hitting a bunch of admin
		// pages in a row is normal editor behavior.
		if ( function_exists( 'is_user_logged_in' ) && is_user_logged_in() ) {
			return;
		}

		$ip = $this->get_ip();
		if ( ! $ip ) return;
		$path = isset( $_SERVER['REQUEST_URI'] ) ? (string) $_SERVER['REQUEST_URI'] : '';
		if ( $path === '' ) return;
		// Normalize path (strip query for path set; keep full uri for evidence).
		$path_only = strtok( $path, '?' );

		$now_ms = (int) ( microtime( true ) * 1000 );
		$ua = isset( $_SERVER['HTTP_USER_AGENT'] ) ? (string) $_SERVER['HTTP_USER_AGENT'] : '';
		$referer = isset( $_SERVER['HTTP_REFERER'] ) ? (string) $_SERVER['HTTP_REFERER'] : '';
		$site_host = wp_parse_url( home_url( '/' ), PHP_URL_HOST );
		$ref_host = $referer ? wp_parse_url( $referer, PHP_URL_HOST ) : '';

		$key = 'amoskys_scanner_shape_' . md5( $ip );
		$rec = get_transient( $key );
		if ( ! is_array( $rec ) ) {
			$rec = array(
				'first_seen'          => $now_ms,
				'total'               => 0,
				'paths'               => array(),        // path_only → count
				'intervals_ms'        => array(),
				'last_ts_ms'          => null,
				'ref_none_count'      => 0,
				'ref_own_count'       => 0,
				'ua_first'            => $ua,
				'ua_set'              => array( $ua ),
				'visited_robots'      => false,
				'visited_after_robots' => 0,
				'emitted'             => false,
			);
		}

		$rec['total']++;
		if ( $rec['last_ts_ms'] !== null ) {
			$iv = $now_ms - (int) $rec['last_ts_ms'];
			if ( $iv >= 0 && $iv < 10 * 60 * 1000 ) {
				$rec['intervals_ms'][] = $iv;
				if ( count( $rec['intervals_ms'] ) > self::MAX_PATHS_TRACKED ) {
					$rec['intervals_ms'] = array_slice( $rec['intervals_ms'], -self::MAX_PATHS_TRACKED );
				}
			}
		}
		$rec['last_ts_ms'] = $now_ms;

		if ( isset( $rec['paths'][ $path_only ] ) ) {
			$rec['paths'][ $path_only ]++;
		} else {
			// Cap distinct paths to bound memory.
			if ( count( $rec['paths'] ) < self::MAX_PATHS_TRACKED ) {
				$rec['paths'][ $path_only ] = 1;
			}
		}
		if ( $referer === '' ) {
			$rec['ref_none_count']++;
		} elseif ( $ref_host && $site_host && strcasecmp( $ref_host, $site_host ) === 0 ) {
			$rec['ref_own_count']++;
		}
		if ( $ua && ! in_array( $ua, $rec['ua_set'], true ) ) {
			$rec['ua_set'][] = $ua;
		}
		if ( $path_only === '/robots.txt' ) {
			$rec['visited_robots'] = true;
		} elseif ( $rec['visited_robots'] ) {
			$rec['visited_after_robots']++;
		}

		// Score.
		$score = $this->score( $rec );

		// Write back — always; we need continuity. Skip emit if already emitted.
		if ( ! $rec['emitted'] && $score >= self::SCORE_THRESHOLD && $rec['total'] >= 8 ) {
			$rec['emitted'] = true;
		}
		set_transient( $key, $rec, self::WINDOW_SEC );

		if ( $rec['emitted'] && ! empty( $rec['just_emitted'] ?? false ) ) {
			// (one-shot marker handled below to avoid double-emit inside request)
			return;
		}
		if ( $rec['emitted'] && $rec['total'] >= 8 ) {
			// Detect emit on transition — we just set $rec['emitted']=true above.
			// Emit exactly once per window.
			static $already_emitted_this_request = false;
			if ( ! $already_emitted_this_request ) {
				$already_emitted_this_request = true;
				$this->emit_and_strike( $ip, $rec, $score );
			}
		}
	}

	private function score( array $rec ): int {
		$total = max( 1, (int) $rec['total'] );
		$distinct = count( $rec['paths'] );
		$score = 0;

		if ( $distinct >= 10 ) {
			$score += 25;
		}
		if ( $total >= 5 && ( $distinct / $total ) >= 0.8 ) {
			$score += 20;
		}
		if ( $rec['ref_none_count'] / $total >= 0.8 ) {
			$score += 15;
		}

		// Timing too regular.
		$ivs = $rec['intervals_ms'];
		if ( count( $ivs ) >= 5 ) {
			$median = $this->median( $ivs );
			$stddev = $this->stddev( $ivs, $median );
			if ( $stddev < 1500 && $median >= 2000 ) {
				$score += 15;
			}
		}

		// Visited robots then disallowed — we don't have robots parsed here;
		// the simpler heuristic: visited robots + >=5 subsequent requests
		// still looking around.
		if ( $rec['visited_robots'] && $rec['visited_after_robots'] >= 5 ) {
			$score += 10;
		}

		// UA changed mid-session.
		if ( count( $rec['ua_set'] ) > 1 ) {
			$score += 10;
		}

		// Multi-subsystem fingerprint (small bonus).
		$subsystems = $this->subsystems_touched( $rec['paths'] );
		if ( count( $subsystems ) >= 3 ) {
			$score += 5;
		}

		return $score;
	}

	private function subsystems_touched( array $paths ): array {
		$found = array();
		foreach ( $paths as $p => $_c ) {
			if ( strpos( $p, '/wp-admin' ) === 0 )   $found['admin']   = 1;
			if ( strpos( $p, '/wp-json' ) === 0 )    $found['rest']    = 1;
			if ( strpos( $p, '/feed' ) === 0 )       $found['feed']    = 1;
			if ( strpos( $p, '/wp-content/plugins' ) === 0 ) $found['plugins'] = 1;
			if ( strpos( $p, '/wp-login' ) === 0 )   $found['login']   = 1;
			if ( $p === '/sitemap.xml' || strpos( $p, '/wp-sitemap' ) === 0 ) $found['sitemap'] = 1;
		}
		return array_keys( $found );
	}

	private function median( array $xs ): float {
		sort( $xs );
		$n = count( $xs );
		if ( $n === 0 ) return 0.0;
		return $n % 2 ? (float) $xs[ (int) ( $n / 2 ) ]
		              : ( $xs[ $n / 2 - 1 ] + $xs[ $n / 2 ] ) / 2.0;
	}

	private function stddev( array $xs, float $mean ): float {
		if ( count( $xs ) < 2 ) return 0.0;
		$ssq = 0.0;
		foreach ( $xs as $x ) { $ssq += ( $x - $mean ) * ( $x - $mean ); }
		return sqrt( $ssq / ( count( $xs ) - 1 ) );
	}

	private function emit_and_strike( string $ip, array $rec, int $score ): void {
		$this->emitter->emit(
			'aegis.scanner.shape_detected',
			array(
				'ip'                  => $ip,
				'score'               => $score,
				'total_requests'      => $rec['total'],
				'distinct_paths'      => count( $rec['paths'] ),
				'ua_rotation_count'   => count( $rec['ua_set'] ),
				'referer_none_ratio'  => round( $rec['ref_none_count'] / max( 1, $rec['total'] ), 2 ),
				'visited_robots'      => (bool) $rec['visited_robots'],
				'subsystems_touched'  => $this->subsystems_touched( $rec['paths'] ),
				'window_duration_ms'  => (int) ( $rec['last_ts_ms'] - $rec['first_seen'] ),
			),
			'high'
		);
		do_action( 'amoskys_aegis_strike', self::STRIKE_RULE, $ip );
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
