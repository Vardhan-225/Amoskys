<?php
/**
 * AMOSKYS Aegis — Event Emitter
 *
 * Single responsibility: construct a canonical Aegis event envelope and
 * ship it to one or more sinks. Sinks today:
 *   1. Local JSONL log (always on, for auditability)
 *   2. Remote AMOSKYS endpoint (optional, configured via settings)
 *
 * Design notes:
 *   - Never blocks the request. Remote POST uses wp_remote_post with a
 *     short timeout + non-blocking mode so a down brain can't brick WP.
 *   - Every event is SHA-256 chain-linked to the previous event for
 *     tamper-evidence (lightweight Proof Spine compatibility).
 *   - Writes use file locking to survive concurrent php-fpm workers.
 *
 * @package AmoskysAegis
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Amoskys_Aegis_Emitter {

	const SCHEMA_VERSION = '1';
	const LOG_FILENAME   = 'events.jsonl';
	const HASH_ALGO      = 'sha256';

	/**
	 * Re-entrancy guard. The emitter calls update_option(), which fires
	 * the 'updated_option' hook, which our options sensor listens on.
	 * Without this flag, emitting an event would recursively emit again
	 * forever, eating PHP-FPM workers until the host OOMs.
	 *
	 * @var bool
	 */
	private static $emitting = false;

	/** @var string Absolute path to the log directory. */
	private $log_dir;

	/** @var string|null Remote AMOSKYS ingest endpoint. */
	private $remote_url;

	/** @var string|null API key for the remote endpoint. */
	private $api_key;

	/** @var string Per-site stable identifier (like a device_id for the fleet). */
	private $site_id;

	public function __construct() {
		// Log dir: inside uploads so it's writable; WP already protects
		// uploads via .htaccess / nginx rules in most setups.
		$uploads        = wp_upload_dir();
		$this->log_dir  = trailingslashit( $uploads['basedir'] ) . 'amoskys-aegis';

		$this->remote_url = get_option( 'amoskys_aegis_remote_url', '' ) ?: null;
		$this->api_key    = get_option( 'amoskys_aegis_api_key', '' ) ?: null;
		$this->site_id    = $this->get_or_create_site_id();
	}

	public function get_log_dir(): string {
		return $this->log_dir;
	}

	/**
	 * Emit an event. Non-blocking, never throws.
	 *
	 * @param string $event_type Dotted event type (e.g., "aegis.auth.login_failed").
	 * @param array  $data       Event-specific payload.
	 * @param string $severity   info | warn | high | critical
	 */
	public function emit( string $event_type, array $data, string $severity = 'info' ): void {
		// Re-entrancy guard — prevents infinite recursion when a sensor
		// fires on an option we updated during our own emit().
		if ( self::$emitting ) {
			return;
		}
		self::$emitting = true;

		// Chain-integrity lock: serialize the read-modify-write of
		// prev_sig across PHP-FPM workers. Without this, concurrent
		// workers read the same prev_sig, emit, and only one wins the
		// option write → chain breaks under load.
		//
		// We flock() the events log file itself as the semaphore. Any
		// worker that would write to the log must hold the lock for
		// the full read-modify-write cycle, not just the file append.
		$lock_path = $this->get_log_dir() . '/.chain.lock';
		if ( ! is_dir( $this->get_log_dir() ) ) {
			wp_mkdir_p( $this->get_log_dir() );
		}
		$lock_fh = @fopen( $lock_path, 'c' );
		$have_lock = false;
		if ( $lock_fh ) {
			// LOCK_EX = exclusive blocking lock. Cap waits to ~2s
			// via a non-blocking retry to avoid deadlocking a
			// request if something goes wrong upstream.
			$deadline = microtime( true ) + 2.0;
			while ( microtime( true ) < $deadline ) {
				if ( flock( $lock_fh, LOCK_EX | LOCK_NB ) ) {
					$have_lock = true;
					break;
				}
				usleep( 2000 ); // 2ms
			}
		}

		try {
			$envelope = $this->build_envelope( $event_type, $data, $severity );
			$this->write_local( $envelope );
			if ( $this->remote_url ) {
				$this->post_remote( $envelope );
			}
		} catch ( \Throwable $e ) {
			// Never break the host site. Best-effort stderr for debugging.
			error_log( 'AMOSKYS Aegis emit failed: ' . $e->getMessage() );
		} finally {
			if ( $have_lock && $lock_fh ) {
				flock( $lock_fh, LOCK_UN );
			}
			if ( $lock_fh ) {
				fclose( $lock_fh );
			}
			self::$emitting = false;
		}
	}

	/**
	 * Build the canonical event envelope.
	 * Superset-compatible with AMOSKYS DeviceTelemetry protobuf so a
	 * bridge service can translate JSON → protobuf without loss.
	 */
	private function build_envelope( string $event_type, array $data, string $severity ): array {
		$now_ns = (int) ( microtime( true ) * 1e9 );
		$prev_sig = get_option( 'amoskys_aegis_prev_sig', '' );

		$body = array(
			'schema_version'    => self::SCHEMA_VERSION,
			'event_id'          => wp_generate_uuid4(),
			'event_type'        => $event_type,
			'event_timestamp_ns' => $now_ns,
			'severity'          => $severity,
			'site_id'           => $this->site_id,
			'site_url'          => get_site_url(),
			'wp_version'        => get_bloginfo( 'version' ),
			'plugin_version'    => AMOSKYS_AEGIS_VERSION,
			'request' => array(
				'method' => isset( $_SERVER['REQUEST_METHOD'] ) ? sanitize_text_field( $_SERVER['REQUEST_METHOD'] ) : null,
				'uri'    => isset( $_SERVER['REQUEST_URI'] ) ? esc_url_raw( $_SERVER['REQUEST_URI'] ) : null,
				'ip'     => $this->get_client_ip(),
				'ua'     => isset( $_SERVER['HTTP_USER_AGENT'] ) ? sanitize_text_field( $_SERVER['HTTP_USER_AGENT'] ) : null,
			),
			'attributes'        => $data,
			'prev_sig'          => $prev_sig ?: null,
		);

		$body['sig'] = hash( self::HASH_ALGO, json_encode( $body, JSON_UNESCAPED_SLASHES ) );
		update_option( 'amoskys_aegis_prev_sig', $body['sig'], false );

		return $body;
	}

	/**
	 * Append to local JSONL log with file locking.
	 */
	private function write_local( array $envelope ): void {
		if ( ! is_dir( $this->log_dir ) ) {
			wp_mkdir_p( $this->log_dir );
			// Lock down the dir
			file_put_contents( $this->log_dir . '/.htaccess', "deny from all\n" );
			file_put_contents( $this->log_dir . '/index.php', "<?php // Silence is golden.\n" );
		}

		$line = json_encode( $envelope, JSON_UNESCAPED_SLASHES ) . "\n";
		$path = $this->log_dir . '/' . self::LOG_FILENAME;
		$fh   = @fopen( $path, 'ab' );
		if ( ! $fh ) {
			return;
		}
		if ( flock( $fh, LOCK_EX ) ) {
			fwrite( $fh, $line );
			fflush( $fh );
			flock( $fh, LOCK_UN );
		}
		fclose( $fh );
	}

	/**
	 * Fire-and-forget POST to AMOSKYS brain.
	 */
	private function post_remote( array $envelope ): void {
		$headers = array(
			'Content-Type' => 'application/json',
		);
		if ( $this->api_key ) {
			$headers['Authorization'] = 'Bearer ' . $this->api_key;
		}

		wp_remote_post(
			$this->remote_url,
			array(
				'method'    => 'POST',
				'timeout'   => 2,
				'blocking'  => false,
				'headers'   => $headers,
				'body'      => wp_json_encode( $envelope ),
				'sslverify' => true,
			)
		);
	}

	/**
	 * Resolve client IP with proxy-awareness.
	 * Falls back to REMOTE_ADDR if no proxy headers trusted.
	 *
	 * SECURITY NOTE: This trusts X-Forwarded-For / CF-Connecting-IP
	 * only when trust_proxy option is set by the admin. Default: off.
	 */
	private function get_client_ip(): ?string {
		$trust_proxy = (bool) get_option( 'amoskys_aegis_trust_proxy', false );

		if ( $trust_proxy ) {
			foreach ( array( 'HTTP_CF_CONNECTING_IP', 'HTTP_X_FORWARDED_FOR', 'HTTP_X_REAL_IP' ) as $hdr ) {
				if ( ! empty( $_SERVER[ $hdr ] ) ) {
					$ip = explode( ',', $_SERVER[ $hdr ] )[0];
					$ip = trim( $ip );
					if ( filter_var( $ip, FILTER_VALIDATE_IP ) ) {
						return $ip;
					}
				}
			}
		}

		return isset( $_SERVER['REMOTE_ADDR'] ) ? $_SERVER['REMOTE_ADDR'] : null;
	}

	/**
	 * Per-site stable identifier. Created once on first emit, persisted.
	 * Equivalent to device_id in the AMOSKYS fleet model.
	 */
	private function get_or_create_site_id(): string {
		$sid = get_option( 'amoskys_aegis_site_id', '' );
		if ( ! $sid ) {
			$sid = substr( hash( 'sha256', get_site_url() . wp_generate_password( 32, true, true ) ), 0, 16 );
			update_option( 'amoskys_aegis_site_id', $sid, false );
		}
		return $sid;
	}
}
