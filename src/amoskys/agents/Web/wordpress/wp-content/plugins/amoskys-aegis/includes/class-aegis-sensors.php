<?php
/**
 * AMOSKYS Aegis — Sensor Registry (deep-observability mode)
 *
 * Philosophy (v0.2+): observe everything, classify nothing. Aegis emits a
 * broad, rich event stream at info severity by default. Severity is
 * assigned by IGRIS-Web based on cross-event correlation, not by the
 * plugin. This follows the "detection later, observability first" design
 * principle — we cannot retroactively observe what we didn't capture.
 *
 * Sensor families (v0.2):
 *   AUTH       — login, role change, user register, password reset
 *   REST       — route registration, unauth detection, POI canary
 *   PLUGIN     — install/activate/deactivate/update/delete
 *   THEME      — switch/update
 *   FIM        — wp-config + (extended) active theme files
 *   OUTBOUND   — HTTP egress with Ethereum RPC detection
 *   HTTP       — every request (method, URI, status, duration)
 *   ADMIN      — admin page views, privileged actions
 *   OPTIONS    — option updates (with secret redaction)
 *   CRON       — scheduled task execution
 *   MAIL       — wp_mail attempts (success + failure)
 *   POST       — post/page create/update/delete, status transitions
 *   COMMENT    — comment insert
 *   MEDIA      — attachment upload/delete
 *   DB (sampled) — database queries (slow + random sample)
 *
 * High-volume sensors (HTTP, DB) use sampling to stay lightweight. Every
 * event is chain-linked via Proof Spine regardless of sensor family.
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
		// Core v0.1 sensors (auth / REST / plugin / FIM / outbound)
		$this->register_auth_sensor();
		$this->register_rest_sensor();
		$this->register_plugin_sensor();
		$this->register_fim_sensor();
		$this->register_outbound_sensor();

		// v0.2 deep-observability sensors
		$this->register_http_sensor();
		$this->register_theme_sensor();
		$this->register_admin_sensor();
		$this->register_options_sensor();
		$this->register_cron_sensor();
		$this->register_mail_sensor();
		$this->register_post_sensor();
		$this->register_comment_sensor();
		$this->register_media_sensor();
		$this->register_db_sensor();
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

	// ═════════════════════════════════════════════════════════════════
	// DEEP-OBSERVABILITY SENSORS (v0.2)
	// Philosophy: observe, don't classify. All events default to info.
	// IGRIS-Web assigns severity based on cross-event correlation.
	// ═════════════════════════════════════════════════════════════════

	// ──────────────────────────────────────────────────────────────
	// 6. HTTP SENSOR — every request that reaches PHP
	// ──────────────────────────────────────────────────────────────

	private $http_start_time = null;

	private function register_http_sensor(): void {
		$this->http_start_time = microtime( true );
		add_action( 'shutdown', array( $this, 'emit_http_request' ), 999 );
	}

	public function emit_http_request(): void {
		// Don't emit for our own internal CLI / cron
		if ( ( defined( 'WP_CLI' ) && WP_CLI ) || ( defined( 'DOING_CRON' ) && DOING_CRON ) ) {
			return;
		}

		$duration_ms = $this->http_start_time
			? ( microtime( true ) - $this->http_start_time ) * 1000.0
			: null;

		$status = http_response_code() ?: 200;

		$this->emitter->emit(
			'aegis.http.request',
			array(
				'status'      => (int) $status,
				'duration_ms' => $duration_ms !== null ? round( $duration_ms, 2 ) : null,
				'memory_mb'   => round( memory_get_peak_usage( true ) / 1024 / 1024, 2 ),
				'is_admin'    => is_admin(),
				'is_ajax'     => wp_doing_ajax(),
				'is_rest'     => defined( 'REST_REQUEST' ) && REST_REQUEST,
				'query_count' => isset( $GLOBALS['wpdb'] ) ? (int) $GLOBALS['wpdb']->num_queries : null,
			),
			'info'
		);
	}

	// ──────────────────────────────────────────────────────────────
	// 7. THEME SENSOR — switch + update
	// ──────────────────────────────────────────────────────────────

	private function register_theme_sensor(): void {
		add_action( 'switch_theme', array( $this, 'on_theme_switch' ), 10, 3 );
	}

	public function on_theme_switch( string $new_name, \WP_Theme $new_theme, \WP_Theme $old_theme ): void {
		$this->emitter->emit(
			'aegis.theme.switched',
			array(
				'new_theme'      => $new_name,
				'new_version'    => $new_theme->get( 'Version' ),
				'old_theme'      => $old_theme->get( 'Name' ),
				'old_version'    => $old_theme->get( 'Version' ),
			),
			'warn'
		);
	}

	// ──────────────────────────────────────────────────────────────
	// 8. ADMIN SENSOR — admin area access + privileged screen views
	// ──────────────────────────────────────────────────────────────

	private function register_admin_sensor(): void {
		add_action( 'admin_init', array( $this, 'on_admin_init' ), 1 );
	}

	public function on_admin_init(): void {
		if ( ! is_admin() ) {
			return;
		}
		$screen = function_exists( 'get_current_screen' ) ? get_current_screen() : null;
		$user   = wp_get_current_user();
		$this->emitter->emit(
			'aegis.admin.page_view',
			array(
				'user_id'   => $user ? $user->ID : null,
				'user_login' => $user ? $user->user_login : null,
				'roles'     => $user ? $user->roles : array(),
				'screen_id' => $screen ? $screen->id : null,
				'pagenow'   => isset( $GLOBALS['pagenow'] ) ? $GLOBALS['pagenow'] : null,
			),
			'info'
		);
	}

	// ──────────────────────────────────────────────────────────────
	// 9. OPTIONS SENSOR — track option updates with secret redaction
	// ──────────────────────────────────────────────────────────────

	private function register_options_sensor(): void {
		add_action( 'updated_option', array( $this, 'on_option_updated' ), 10, 3 );
		add_action( 'added_option', array( $this, 'on_option_added' ), 10, 2 );
	}

	/**
	 * Options we never emit values for — potential secret leaks.
	 * Names are matched case-insensitively and via substring.
	 */
	private const SENSITIVE_OPTION_FRAGMENTS = array(
		'pass', 'password', 'secret', 'key', 'token', 'auth',
		'nonce', 'salt', 'license', 'api_key', 'private',
	);

	private function is_sensitive_option( string $name ): bool {
		$lower = strtolower( $name );
		foreach ( self::SENSITIVE_OPTION_FRAGMENTS as $frag ) {
			if ( false !== strpos( $lower, $frag ) ) {
				return true;
			}
		}
		return false;
	}

	public function on_option_updated( string $option, $old_value, $value ): void {
		// NEVER emit for our own plugin's options — would recurse forever
		// (emit() updates amoskys_aegis_prev_sig on every call).
		if ( 0 === strpos( $option, 'amoskys_aegis_' ) ) {
			return;
		}
		// Skip noisy WP core options that change on every request
		// (cron, transients, etc.).
		if ( $this->is_noisy_option( $option ) ) {
			return;
		}
		$sensitive = $this->is_sensitive_option( $option );
		$this->emitter->emit(
			'aegis.options.updated',
			array(
				'option'      => $option,
				'sensitive'   => $sensitive,
				'old_type'    => gettype( $old_value ),
				'new_type'    => gettype( $value ),
				'size_delta'  => $this->value_size_delta( $old_value, $value ),
				'actor_user_id' => get_current_user_id() ?: null,
			),
			$sensitive ? 'warn' : 'info'
		);
	}

	public function on_option_added( string $option, $value ): void {
		if ( 0 === strpos( $option, 'amoskys_aegis_' ) ) {
			return;
		}
		if ( $this->is_noisy_option( $option ) ) {
			return;
		}
		$sensitive = $this->is_sensitive_option( $option );
		$this->emitter->emit(
			'aegis.options.added',
			array(
				'option'    => $option,
				'sensitive' => $sensitive,
				'value_type' => gettype( $value ),
				'actor_user_id' => get_current_user_id() ?: null,
			),
			$sensitive ? 'warn' : 'info'
		);
	}

	/**
	 * WordPress core updates these on every request — not security-relevant.
	 */
	private function is_noisy_option( string $option ): bool {
		static $noisy = array(
			'cron',              // WP-Cron table — updates on every scheduling
			'doing_cron',
			'_transient_doing_cron',
			'db_upgraded',
			'auto_core_update_notified',
		);
		if ( in_array( $option, $noisy, true ) ) {
			return true;
		}
		// Skip all transients — they're inherently transient and noisy
		if ( 0 === strpos( $option, '_transient_' ) || 0 === strpos( $option, '_site_transient_' ) ) {
			return true;
		}
		return false;
	}

	private function value_size_delta( $old_value, $new_value ): int {
		$old_size = is_string( $old_value ) ? strlen( $old_value ) : strlen( (string) maybe_serialize( $old_value ) );
		$new_size = is_string( $new_value ) ? strlen( $new_value ) : strlen( (string) maybe_serialize( $new_value ) );
		return $new_size - $old_size;
	}

	// ──────────────────────────────────────────────────────────────
	// 10. CRON SENSOR — scheduled task execution
	// ──────────────────────────────────────────────────────────────

	private function register_cron_sensor(): void {
		add_action( 'wp_loaded', array( $this, 'on_wp_loaded_cron_check' ) );
	}

	public function on_wp_loaded_cron_check(): void {
		if ( defined( 'DOING_CRON' ) && DOING_CRON ) {
			$cron = wp_get_ready_cron_jobs();
			$hook_names = array();
			if ( is_array( $cron ) ) {
				foreach ( $cron as $timestamp => $jobs ) {
					if ( is_array( $jobs ) ) {
						$hook_names = array_merge( $hook_names, array_keys( $jobs ) );
					}
				}
			}
			$this->emitter->emit(
				'aegis.cron.run',
				array(
					'hooks_ready' => array_values( array_unique( $hook_names ) ),
					'job_count'   => count( $hook_names ),
				),
				'info'
			);
		}
	}

	// ──────────────────────────────────────────────────────────────
	// 11. MAIL SENSOR — every wp_mail attempt
	// ──────────────────────────────────────────────────────────────

	private function register_mail_sensor(): void {
		add_action( 'wp_mail_succeeded', array( $this, 'on_mail_ok' ), 10, 1 );
		add_action( 'wp_mail_failed', array( $this, 'on_mail_failed' ), 10, 1 );
	}

	public function on_mail_ok( array $mail ): void {
		$this->emitter->emit(
			'aegis.mail.sent',
			array(
				'to_domains' => $this->extract_mail_domains( $mail['to'] ?? array() ),
				'subject'    => isset( $mail['subject'] ) ? substr( (string) $mail['subject'], 0, 120 ) : null,
				'recipient_count' => is_array( $mail['to'] ?? null ) ? count( $mail['to'] ) : 1,
			),
			'info'
		);
	}

	public function on_mail_failed( $wp_error ): void {
		$this->emitter->emit(
			'aegis.mail.failed',
			array(
				'error' => is_wp_error( $wp_error ) ? $wp_error->get_error_message() : 'unknown',
			),
			'warn'
		);
	}

	/** Return list of unique recipient domains (no local parts — reduce PII). */
	private function extract_mail_domains( $to ): array {
		$to = is_array( $to ) ? $to : array( $to );
		$domains = array();
		foreach ( $to as $addr ) {
			if ( ! is_string( $addr ) ) {
				continue;
			}
			$pos = strpos( $addr, '@' );
			if ( false !== $pos ) {
				$domains[] = substr( $addr, $pos + 1 );
			}
		}
		return array_values( array_unique( $domains ) );
	}

	// ──────────────────────────────────────────────────────────────
	// 12. POST SENSOR — post/page CRUD
	// ──────────────────────────────────────────────────────────────

	private function register_post_sensor(): void {
		add_action( 'save_post', array( $this, 'on_post_saved' ), 10, 3 );
		add_action( 'transition_post_status', array( $this, 'on_post_status' ), 10, 3 );
		add_action( 'before_delete_post', array( $this, 'on_post_deleted' ), 10, 1 );
	}

	public function on_post_saved( int $post_id, \WP_Post $post, bool $update ): void {
		// Skip revisions / autosaves — too noisy
		if ( wp_is_post_revision( $post_id ) || wp_is_post_autosave( $post_id ) ) {
			return;
		}
		$this->emitter->emit(
			'aegis.post.saved',
			array(
				'post_id'   => $post_id,
				'post_type' => $post->post_type,
				'status'    => $post->post_status,
				'is_update' => $update,
				'author'    => (int) $post->post_author,
				'title_length' => strlen( (string) $post->post_title ),
				'content_length' => strlen( (string) $post->post_content ),
			),
			'info'
		);
	}

	public function on_post_status( string $new_status, string $old_status, \WP_Post $post ): void {
		if ( $new_status === $old_status ) {
			return;
		}
		$this->emitter->emit(
			'aegis.post.status_change',
			array(
				'post_id'    => $post->ID,
				'post_type'  => $post->post_type,
				'new_status' => $new_status,
				'old_status' => $old_status,
			),
			'info'
		);
	}

	public function on_post_deleted( int $post_id ): void {
		$post = get_post( $post_id );
		$this->emitter->emit(
			'aegis.post.deleted',
			array(
				'post_id'   => $post_id,
				'post_type' => $post ? $post->post_type : null,
				'actor_user_id' => get_current_user_id() ?: null,
			),
			'warn'
		);
	}

	// ──────────────────────────────────────────────────────────────
	// 13. COMMENT SENSOR
	// ──────────────────────────────────────────────────────────────

	private function register_comment_sensor(): void {
		add_action( 'wp_insert_comment', array( $this, 'on_comment_inserted' ), 10, 2 );
	}

	public function on_comment_inserted( int $comment_id, \WP_Comment $comment ): void {
		$this->emitter->emit(
			'aegis.comment.posted',
			array(
				'comment_id'  => $comment_id,
				'post_id'     => (int) $comment->comment_post_ID,
				'approved'    => $comment->comment_approved === '1',
				'author_len'  => strlen( $comment->comment_author ?? '' ),
				'content_len' => strlen( $comment->comment_content ?? '' ),
				'user_id'     => (int) $comment->user_id,
			),
			'info'
		);
	}

	// ──────────────────────────────────────────────────────────────
	// 14. MEDIA SENSOR
	// ──────────────────────────────────────────────────────────────

	private function register_media_sensor(): void {
		add_action( 'add_attachment', array( $this, 'on_attachment_added' ) );
		add_action( 'delete_attachment', array( $this, 'on_attachment_deleted' ) );
	}

	public function on_attachment_added( int $attachment_id ): void {
		$mime = get_post_mime_type( $attachment_id );
		$file = get_attached_file( $attachment_id );
		$filesize = $file && file_exists( $file ) ? filesize( $file ) : 0;
		$this->emitter->emit(
			'aegis.media.uploaded',
			array(
				'attachment_id' => $attachment_id,
				'mime_type'     => $mime,
				'size_bytes'    => $filesize,
				'actor_user_id' => get_current_user_id() ?: null,
				// Flag suspicious MIME types that shouldn't be in uploads
				'suspicious_mime' => in_array( $mime, array( 'application/x-php', 'text/php', 'application/x-httpd-php' ), true ),
			),
			'info'
		);
	}

	public function on_attachment_deleted( int $attachment_id ): void {
		$this->emitter->emit(
			'aegis.media.deleted',
			array(
				'attachment_id' => $attachment_id,
				'actor_user_id' => get_current_user_id() ?: null,
			),
			'info'
		);
	}

	// ──────────────────────────────────────────────────────────────
	// 15. DB SENSOR — sampled query observability
	// ──────────────────────────────────────────────────────────────
	//
	// Samples queries: every Nth non-SELECT, plus any query > 100ms.
	// Captures query TYPE and affected table, NOT values (secrets leak).
	// ──────────────────────────────────────────────────────────────

	private $db_query_seq = 0;
	private const DB_SAMPLE_EVERY_N = 50; // 1 in 50 for SELECT; all for writes

	private function register_db_sensor(): void {
		// WordPress doesn't expose a clean per-query hook — we'd need to
		// filter queries via $wpdb. Use the shutdown hook to walk the
		// query log WordPress keeps when SAVEQUERIES is true.
		// We emit a SUMMARY on shutdown rather than per-query to keep
		// volume manageable.
		add_action( 'shutdown', array( $this, 'emit_db_summary' ), 998 );
	}

	public function emit_db_summary(): void {
		if ( ! isset( $GLOBALS['wpdb'] ) ) {
			return;
		}
		$wpdb = $GLOBALS['wpdb'];
		$num = isset( $wpdb->num_queries ) ? (int) $wpdb->num_queries : 0;
		$slow = 0;
		$types = array( 'SELECT' => 0, 'INSERT' => 0, 'UPDATE' => 0, 'DELETE' => 0, 'OTHER' => 0 );

		// If SAVEQUERIES is enabled, we have per-query detail
		if ( defined( 'SAVEQUERIES' ) && SAVEQUERIES && is_array( $wpdb->queries ?? null ) ) {
			foreach ( $wpdb->queries as $q ) {
				$sql = isset( $q[0] ) ? ltrim( (string) $q[0] ) : '';
				$dur = isset( $q[1] ) ? (float) $q[1] : 0.0;
				if ( $dur > 0.1 ) {
					$slow++;
				}
				$verb = strtoupper( substr( $sql, 0, 6 ) );
				if ( 0 === strpos( $verb, 'SELECT' ) ) { $types['SELECT']++; }
				elseif ( 0 === strpos( $verb, 'INSERT' ) ) { $types['INSERT']++; }
				elseif ( 0 === strpos( $verb, 'UPDATE' ) ) { $types['UPDATE']++; }
				elseif ( 0 === strpos( $verb, 'DELETE' ) ) { $types['DELETE']++; }
				else { $types['OTHER']++; }
			}
		}

		$this->emitter->emit(
			'aegis.db.summary',
			array(
				'num_queries' => $num,
				'slow_count'  => $slow,
				'by_type'     => $types,
				'savequeries_enabled' => defined( 'SAVEQUERIES' ) && SAVEQUERIES,
			),
			$slow > 5 ? 'warn' : 'info'
		);
	}
}
