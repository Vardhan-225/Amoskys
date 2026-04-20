<?php
/**
 * AMOSKYS Aegis — SSRF Runtime Classifier (v0.9)
 *
 * Defensive pair to argos/ast/ssrf.py. The AST scanner catches the
 * plugin code that CAN BE exploited for SSRF; this sensor catches the
 * exploitation at the moment a WordPress outbound HTTP request is
 * about to leave the box.
 *
 * Hook
 * ─────────────────────────────────────────────────────────────────
 * WordPress fires `pre_http_request` just before every wp_remote_*
 * call dispatches. The filter signature is:
 *     ( $preempt, $args, $url )
 * Returning $preempt (a WP_Error or response array) short-circuits
 * the request. We only OBSERVE and RETURN $preempt unchanged — the
 * sensor never blocks an outbound request from this hook (other
 * security plugins may want to). Our response is the block on the
 * INBOUND IP that triggered the SSRF attempt.
 *
 * What we flag
 * ─────────────────────────────────────────────────────────────────
 *
 *   CLOUD_METADATA_TARGET
 *     Host resolves to or textually matches:
 *       - 169.254.169.254          (AWS EC2 IMDS, Azure IMDS)
 *       - metadata.google.internal (GCP)
 *       - metadata.packet.net      (Equinix)
 *       - fd00:ec2::254            (AWS IPv6)
 *     No legitimate WP plugin requests these. Critical.
 *
 *   LOOPBACK_TARGET
 *     127.0.0.0/8, ::1, or the host 'localhost'.
 *     Rare in legit plugin usage; flag as critical.
 *
 *   PRIVATE_NETWORK_TARGET
 *     RFC 1918 (10/8, 172.16/12, 192.168/16), RFC 6598 (100.64/10),
 *     link-local (169.254/16), IPv6 ULA (fc00::/7).
 *     Plugins fetching from private networks are rare; high.
 *
 *   NON_HTTP_SCHEME
 *     file://, gopher://, dict://, ftp://, tftp://, ldap://, sftp://
 *     on a wp_remote_* URL. Critical (e.g., gopher can talk to
 *     internal Redis / SMTP).
 *
 * Response
 * ─────────────────────────────────────────────────────────────────
 * All hits emit `aegis.outbound.ssrf_attempt` at severity:
 *   - critical for CLOUD_METADATA_TARGET, NON_HTTP_SCHEME
 *   - critical for LOOPBACK_TARGET when the loopback isn't a WP-
 *     internal wp-cron request (we fingerprint wp-cron UA)
 *   - high for PRIVATE_NETWORK_TARGET
 *
 * Strike `ssrf_attempt` (threshold=1 for critical hits) fires on the
 * INBOUND client IP — because the attacker's inbound request is what
 * triggered the plugin to emit the outbound SSRF-y call.
 *
 * @package AmoskysAegis
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Amoskys_Aegis_Ssrf_Sensor {

	/** @var Amoskys_Aegis_Emitter */
	private $emitter;

	const STRIKE_RULE = 'ssrf_attempt';

	const CLOUD_METADATA_HOSTS = array(
		'metadata.google.internal',
		'metadata.packet.net',
		'metadata.amazonaws.com',
		'metadata.aws.cloud',
		'metadata.us-east-1.ec2.internal',
		'169.254.169.254',
		'fd00:ec2::254',
	);

	const NON_HTTP_SCHEMES = array(
		'file', 'gopher', 'dict', 'ftp', 'tftp', 'ldap', 'sftp',
		'expect', 'jar', 'ogg', 'php', 'phar',
	);

	public function __construct( Amoskys_Aegis_Emitter $emitter ) {
		$this->emitter = $emitter;
	}

	public function register(): void {
		// pre_http_request receives (bool|array|WP_Error $preempt, array $args, string $url)
		// and must RETURN $preempt unchanged (false means "continue").
		add_filter( 'pre_http_request', array( $this, 'inspect_outbound' ), 0, 3 );
	}

	/**
	 * @return mixed  $preempt unchanged
	 */
	public function inspect_outbound( $preempt, $args, $url ) {
		if ( ! is_string( $url ) || $url === '' ) {
			return $preempt;
		}

		$parts = wp_parse_url( $url );
		if ( ! is_array( $parts ) ) {
			return $preempt;
		}

		$scheme = isset( $parts['scheme'] ) ? strtolower( (string) $parts['scheme'] ) : '';
		$host   = isset( $parts['host'] )   ? strtolower( (string) $parts['host'] )   : '';
		$port   = isset( $parts['port'] )   ? (int) $parts['port']                    : 0;

		$classes = array();
		$detail = array( 'scheme' => $scheme, 'host' => $host, 'port' => $port );

		// 1. NON_HTTP_SCHEME
		if ( $scheme && ! in_array( $scheme, array( 'http', 'https' ), true ) ) {
			if ( in_array( $scheme, self::NON_HTTP_SCHEMES, true ) ) {
				$classes[] = 'NON_HTTP_SCHEME';
			}
		}

		// 2. CLOUD_METADATA_TARGET
		if ( $host && in_array( $host, self::CLOUD_METADATA_HOSTS, true ) ) {
			$classes[] = 'CLOUD_METADATA_TARGET';
		}

		// 3. LOOPBACK_TARGET
		if ( $host === 'localhost' || $this->is_loopback_ip( $host ) ) {
			$classes[] = 'LOOPBACK_TARGET';
		}

		// 4. PRIVATE_NETWORK_TARGET
		if ( ! in_array( 'LOOPBACK_TARGET', $classes, true )
		  && $this->is_private_network( $host ) ) {
			$classes[] = 'PRIVATE_NETWORK_TARGET';
		}

		if ( empty( $classes ) ) {
			return $preempt;
		}

		// Severity selection.
		$critical_classes = array( 'CLOUD_METADATA_TARGET', 'NON_HTTP_SCHEME', 'LOOPBACK_TARGET' );
		$top_sev = 'high';
		foreach ( $critical_classes as $c ) {
			if ( in_array( $c, $classes, true ) ) { $top_sev = 'critical'; break; }
		}

		// Exempt WP's own internal loopback wp-cron call (WordPress posts
		// to its own URL to run scheduled tasks). The UA always says
		// "WordPress/x.y; https://site/" for these.
		$inbound_ua = isset( $_SERVER['HTTP_USER_AGENT'] ) ? (string) $_SERVER['HTTP_USER_AGENT'] : '';
		$inbound_uri = isset( $_SERVER['REQUEST_URI'] ) ? (string) $_SERVER['REQUEST_URI'] : '';
		$is_wp_self_cron = ( strpos( $inbound_ua, 'WordPress/' ) === 0 )
		                || ( strpos( $inbound_uri, 'wp-cron.php' ) !== false );
		if ( $is_wp_self_cron && $classes === array( 'LOOPBACK_TARGET' ) ) {
			return $preempt;
		}

		$inbound_ip = $this->get_inbound_ip();

		$this->emitter->emit(
			'aegis.outbound.ssrf_attempt',
			array(
				'inbound_ip'  => $inbound_ip,
				'inbound_uri' => substr( $inbound_uri, 0, 200 ),
				'inbound_ua'  => substr( $inbound_ua, 0, 120 ),
				'target_url'  => substr( $url, 0, 400 ),
				'classes'     => $classes,
				'detail'      => $detail,
			),
			$top_sev
		);

		// Strike the inbound attacker IP on critical classifications only.
		if ( $top_sev === 'critical' && $inbound_ip ) {
			do_action( 'amoskys_aegis_strike', self::STRIKE_RULE, $inbound_ip );
		}

		return $preempt;
	}

	private function is_loopback_ip( string $host ): bool {
		if ( $host === '' ) {
			return false;
		}
		if ( $host === '::1' ) {
			return true;
		}
		if ( filter_var( $host, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 ) ) {
			return strpos( $host, '127.' ) === 0;
		}
		return false;
	}

	private function is_private_network( string $host ): bool {
		if ( ! filter_var( $host, FILTER_VALIDATE_IP ) ) {
			return false;
		}
		// RFC 1918 + RFC 6598 + link-local. PHP's filter_var with
		// FILTER_FLAG_NO_PRIV_RANGE / NO_RES_RANGE returns false when
		// the address IS in that range.
		$ok = filter_var( $host, FILTER_VALIDATE_IP,
			FILTER_FLAG_IPV4 | FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE );
		return $ok === false;
	}

	private function get_inbound_ip(): string {
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
