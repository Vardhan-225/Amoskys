<?php
/**
 * AMOSKYS Aegis — Sensor Registry
 *
 * All defensive sensors live here. Each sensor is a small set of WordPress
 * hooks that, when fired, construct a domain-specific event and hand it
 * to the Emitter.
 *
 * Sensors (v0):
 *   1. Auth     — login success/fail, admin privilege changes
 *   2. REST     — route registration, unauth route detection
 *   3. Plugin   — install, activate, deactivate, update, delete
 *   4. FIM      — wp-config.php modification detection
 *   5. Outbound — HTTP egress from PHP (wp_remote_* hooks)
 *
 * Deliberately NOT in v0:
 *   - SQL inspection (needs query filter; high volume, do later)
 *   - Full WAF rule engine (separate module; ship OWASP CRS via mod_security)
 *   - Googlebot cloaking detection (needs side-channel, later)
 *
 * @package AmoskysAegis
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Amoskys_Aegis_Sensors {

	/** @var Amoskys_Aegis_Emitter */
	private $emitter;

	public function __construct( Amoskys_Aegis_Emitter $emitter ) {
		$this->emitter = $emitter;
	}

	/**
	 * Register all sensor hooks. Called on plugins_loaded@1 so we run
	 * before most third-party plugins initialize.
	 */
	public function register(): void {
		$this->register_auth_sensor();
		$this->register_rest_sensor();
		$this->register_plugin_sensor();
		$this->register_fim_sensor();
		$this->register_outbound_sensor();
	}

	// ─────────────────────────────────────────────────────────────
	// 1. AUTH SENSOR
	// ─────────────────────────────────────────────────────────────

	private function register_auth_sensor(): void {
		add_action( 'wp_login', array( $this, 'on_login_success' ), 10, 2 );
		add_action( 'wp_login_failed', array( $this, 'on_login_failed' ), 10, 2 );
		add_action( 'set_user_role', array( $this, 'on_role_change' ), 10, 3 );
		add_action( 'user_register', array( $this, 'on_user_registered' ), 10, 1 );
		add_action( 'password_reset', array( $this, 'on_password_reset' ), 10, 2 );
	}

	public function on_login_success( string $user_login, \WP_User $user ): void {
		$this->emitter->emit(
			'aegis.auth.login_success',
			array(
				'user_id'    => $user->ID,
				'user_login' => $user_login,
				'roles'      => $user->roles,
				'is_admin'   => in_array( 'administrator', $user->roles, true ),
			),
			in_array( 'administrator', $user->roles, true ) ? 'warn' : 'info'
		);
	}

	public function on_login_failed( string $user_login, $error ): void {
		$this->emitter->emit(
			'aegis.auth.login_failed',
			array(
				'user_login' => $user_login,
				'error_code' => is_wp_error( $error ) ? $error->get_error_code() : 'unknown',
			),
			'warn'
		);
	}

	public function on_role_change( int $user_id, string $role, array $old_roles ): void {
		$severity = in_array( 'administrator', array( $role ), true ) ? 'high' : 'info';
		$this->emitter->emit(
			'aegis.auth.role_change',
			array(
				'user_id'   => $user_id,
				'new_role'  => $role,
				'old_roles' => $old_roles,
				'elevated'  => 'administrator' === $role && ! in_array( 'administrator', $old_roles, true ),
			),
			$severity
		);
	}

	public function on_user_registered( int $user_id ): void {
		$user = get_user_by( 'id', $user_id );
		$this->emitter->emit(
			'aegis.auth.user_registered',
			array(
				'user_id'    => $user_id,
				'user_login' => $user ? $user->user_login : null,
				'roles'      => $user ? $user->roles : array(),
			),
			'info'
		);
	}

	public function on_password_reset( \WP_User $user, string $new_pass ): void {
		$this->emitter->emit(
			'aegis.auth.password_reset',
			array(
				'user_id'    => $user->ID,
				'user_login' => $user->user_login,
				'is_admin'   => in_array( 'administrator', $user->roles, true ),
			),
			'info'
		);
	}

	// ─────────────────────────────────────────────────────────────
	// 2. REST ROUTE SENSOR
	// This is THE sensor for the EssentialPlugin attack class:
	// plugin registers an unauth REST route → we flag it.
	// ─────────────────────────────────────────────────────────────

	private function register_rest_sensor(): void {
		add_action( 'rest_api_init', array( $this, 'on_rest_api_init' ), PHP_INT_MAX );
		add_filter( 'rest_pre_dispatch', array( $this, 'on_rest_pre_dispatch' ), 10, 3 );
	}

	public function on_rest_api_init(): void {
		global $wp_rest_server;
		if ( ! $wp_rest_server ) {
			return;
		}

		$routes = $wp_rest_server->get_routes();
		$unauth = array();
		$total  = 0;

		foreach ( $routes as $route => $handlers ) {
			foreach ( $handlers as $handler ) {
				$total++;
				$cb = isset( $handler['permission_callback'] ) ? $handler['permission_callback'] : null;

				// The textbook dangerous pattern: __return_true
				if ( '__return_true' === $cb || ( is_string( $cb ) && '__return_true' === $cb ) ) {
					$unauth[] = array(
						'route'   => $route,
						'methods' => array_keys( $handler['methods'] ),
					);
				}
			}
		}

		if ( ! empty( $unauth ) ) {
			$this->emitter->emit(
				'aegis.rest.unauth_routes_detected',
				array(
					'total_routes'   => $total,
					'unauth_count'   => count( $unauth ),
					'unauth_routes'  => $unauth,
				),
				'high'
			);
		}
	}

	public function on_rest_pre_dispatch( $result, $server, $request ) {
		// Hot path — keep minimal. Just record route access with severity
		// bumped if we detect serialized-object indicators in the body
		// (PHP object injection canary).
		$route  = $request->get_route();
		$method = $request->get_method();
		$body   = $request->get_body();

		$poi_indicators = 0;
		if ( $body && is_string( $body ) ) {
			// Classic PHP serialize signatures
			if ( preg_match( '/O:\d+:"/', $body ) ) { $poi_indicators++; }
			if ( preg_match( '/a:\d+:{/', $body ) ) { $poi_indicators++; }
			if ( preg_match( '/s:\d+:"/', $body ) ) { $poi_indicators++; }
		}

		if ( $poi_indicators > 0 ) {
			$this->emitter->emit(
				'aegis.rest.poi_canary',
				array(
					'route'      => $route,
					'method'     => $method,
					'indicators' => $poi_indicators,
					'body_len'   => strlen( $body ?? '' ),
				),
				'critical'
			);
		}

		return $result;
	}

	// ─────────────────────────────────────────────────────────────
	// 3. PLUGIN LIFECYCLE SENSOR
	// ─────────────────────────────────────────────────────────────

	private function register_plugin_sensor(): void {
		add_action( 'activated_plugin', array( $this, 'on_plugin_activated' ), 10, 2 );
		add_action( 'deactivated_plugin', array( $this, 'on_plugin_deactivated' ), 10, 2 );
		add_action( 'upgrader_process_complete', array( $this, 'on_upgrader_complete' ), 10, 2 );
		add_action( 'delete_plugin', array( $this, 'on_plugin_deleted' ), 10, 1 );
	}

	public function on_plugin_activated( string $plugin, bool $network_wide ): void {
		$this->emitter->emit(
			'aegis.plugin.activated',
			array(
				'plugin'       => $plugin,
				'network_wide' => $network_wide,
				'data'         => $this->get_plugin_data( $plugin ),
			),
			'warn'
		);
	}

	public function on_plugin_deactivated( string $plugin, bool $network_wide ): void {
		$this->emitter->emit(
			'aegis.plugin.deactivated',
			array(
				'plugin'       => $plugin,
				'network_wide' => $network_wide,
			),
			'info'
		);
	}

	/**
	 * The hook for the EssentialPlugin class of attack — fires on any
	 * plugin upgrade, giving us a chance to compare before/after.
	 */
	public function on_upgrader_complete( $upgrader, array $options ): void {
		if ( isset( $options['type'] ) && 'plugin' === $options['type'] ) {
			$plugins = isset( $options['plugins'] ) ? $options['plugins'] : array();
			foreach ( $plugins as $plugin ) {
				$this->emitter->emit(
					'aegis.plugin.updated',
					array(
						'plugin'      => $plugin,
						'action'      => isset( $options['action'] ) ? $options['action'] : 'unknown',
						'data'        => $this->get_plugin_data( $plugin ),
					),
					'high' // Always high severity — supply chain entry point
				);
			}
		}
	}

	public function on_plugin_deleted( string $plugin ): void {
		$this->emitter->emit(
			'aegis.plugin.deleted',
			array( 'plugin' => $plugin ),
			'warn'
		);
	}

	private function get_plugin_data( string $plugin ): array {
		if ( ! function_exists( 'get_plugin_data' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}
		$path = WP_PLUGIN_DIR . '/' . $plugin;
		if ( ! file_exists( $path ) ) {
			return array();
		}
		$data = get_plugin_data( $path, false, false );
		return array(
			'name'        => $data['Name'] ?? null,
			'version'     => $data['Version'] ?? null,
			'author'      => $data['Author'] ?? null,
			'author_uri'  => $data['AuthorURI'] ?? null,
			'plugin_uri'  => $data['PluginURI'] ?? null,
		);
	}

	// ─────────────────────────────────────────────────────────────
	// 4. FIM SENSOR — wp-config.php integrity
	// ─────────────────────────────────────────────────────────────

	private function register_fim_sensor(): void {
		// Run on shutdown so we don't add request latency. Checked every
		// request; actual hash is cheap on a 2-4KB file.
		add_action( 'shutdown', array( $this, 'check_wpconfig_integrity' ) );
	}

	public function check_wpconfig_integrity(): void {
		$path = ABSPATH . 'wp-config.php';
		if ( ! file_exists( $path ) ) {
			return;
		}

		$current_hash = hash_file( 'sha256', $path );
		$baseline_hash = get_option( 'amoskys_aegis_wpconfig_hash', '' );

		if ( ! $baseline_hash ) {
			// First time — establish baseline
			update_option( 'amoskys_aegis_wpconfig_hash', $current_hash );
			update_option( 'amoskys_aegis_wpconfig_size', filesize( $path ) );
			return;
		}

		if ( $current_hash !== $baseline_hash ) {
			$this->emitter->emit(
				'aegis.fim.wpconfig_modified',
				array(
					'path'           => $path,
					'baseline_hash'  => substr( $baseline_hash, 0, 16 ),
					'current_hash'   => substr( $current_hash, 0, 16 ),
					'baseline_size'  => (int) get_option( 'amoskys_aegis_wpconfig_size', 0 ),
					'current_size'   => filesize( $path ),
					'size_delta'     => filesize( $path ) - (int) get_option( 'amoskys_aegis_wpconfig_size', 0 ),
				),
				'critical'
			);
			// Update baseline so we don't scream every request. Real
			// response should be operator-acknowledged; v0 just dedups.
			update_option( 'amoskys_aegis_wpconfig_hash', $current_hash );
			update_option( 'amoskys_aegis_wpconfig_size', filesize( $path ) );
		}
	}

	// ─────────────────────────────────────────────────────────────
	// 5. OUTBOUND HTTP SENSOR
	// Catches plugins calling home to unexpected hosts.
	// The EssentialPlugin Ethereum JSON-RPC beacon would hit here.
	// ─────────────────────────────────────────────────────────────

	private function register_outbound_sensor(): void {
		add_filter( 'pre_http_request', array( $this, 'on_pre_http_request' ), 10, 3 );
	}

	public function on_pre_http_request( $pre, array $args, string $url ) {
		$host = wp_parse_url( $url, PHP_URL_HOST );
		if ( ! $host ) {
			return $pre;
		}

		// Look for Ethereum JSON-RPC indicators in the body
		$body = isset( $args['body'] ) ? $args['body'] : '';
		$rpc_signals = 0;
		if ( is_string( $body ) ) {
			if ( false !== stripos( $body, 'eth_call' ) )            { $rpc_signals++; }
			if ( false !== stripos( $body, 'eth_getTransaction' ) )  { $rpc_signals++; }
			if ( false !== stripos( $body, 'jsonrpc' ) && false !== stripos( $body, '2.0' ) ) { $rpc_signals++; }
		}

		$severity = 'info';
		$event    = 'aegis.outbound.http';
		if ( $rpc_signals >= 2 ) {
			$severity = 'critical';
			$event    = 'aegis.outbound.ethereum_rpc';
		}

		$this->emitter->emit(
			$event,
			array(
				'host'    => $host,
				'method'  => isset( $args['method'] ) ? $args['method'] : 'GET',
				'rpc_signals' => $rpc_signals,
				'body_len' => is_string( $body ) ? strlen( $body ) : 0,
			),
			$severity
		);

		return $pre; // Pass through — v0 only observes, doesn't block
	}
}
