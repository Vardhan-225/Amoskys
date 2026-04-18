<?php
/**
 * Plugin Name:       AMOSKYS Aegis
 * Plugin URI:        https://amoskys.com/aegis
 * Description:       Defensive sensor + event emitter for AMOSKYS Web. Watches authentication, REST routes, plugin lifecycle, file integrity (wp-config), and outbound network calls. Ships signed events to the AMOSKYS brain (IGRIS) for correlation and response.
 * Version:           0.1.0-alpha
 * Requires at least: 6.0
 * Requires PHP:      8.0
 * Author:            AMOSKYS
 * Author URI:        https://amoskys.com
 * License:           GPL v2 or later
 * License URI:       https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain:       amoskys-aegis
 *
 * @package AmoskysAegis
 */

// Direct access guard — WordPress security 101
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

// Plugin constants
define( 'AMOSKYS_AEGIS_VERSION', '0.1.0-alpha' );
define( 'AMOSKYS_AEGIS_PLUGIN_FILE', __FILE__ );
define( 'AMOSKYS_AEGIS_PLUGIN_DIR', plugin_dir_path( __FILE__ ) );
define( 'AMOSKYS_AEGIS_PLUGIN_URL', plugin_dir_url( __FILE__ ) );

// Load core components
require_once AMOSKYS_AEGIS_PLUGIN_DIR . 'includes/class-aegis-emitter.php';
require_once AMOSKYS_AEGIS_PLUGIN_DIR . 'includes/class-aegis-sensors.php';
require_once AMOSKYS_AEGIS_PLUGIN_DIR . 'includes/class-aegis-settings.php';

/**
 * Core plugin bootstrap.
 *
 * Keeps the hot path lean — just wires the sensors to WordPress hooks
 * and hands off all event construction + delivery to the Emitter.
 */
final class Amoskys_Aegis {

	/** @var Amoskys_Aegis|null */
	private static $instance = null;

	/** @var Amoskys_Aegis_Emitter */
	private $emitter;

	/** @var Amoskys_Aegis_Sensors */
	private $sensors;

	/** @var Amoskys_Aegis_Settings */
	private $settings;

	public static function instance(): self {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	private function __construct() {
		$this->emitter  = new Amoskys_Aegis_Emitter();
		$this->sensors  = new Amoskys_Aegis_Sensors( $this->emitter );
		$this->settings = new Amoskys_Aegis_Settings();

		// Activate/deactivate lifecycle
		register_activation_hook( AMOSKYS_AEGIS_PLUGIN_FILE, array( $this, 'activate' ) );
		register_deactivation_hook( AMOSKYS_AEGIS_PLUGIN_FILE, array( $this, 'deactivate' ) );

		// Wire sensors at plugins_loaded priority 1 so we run BEFORE
		// most other plugins — critical for intercepting hostile plugin
		// registrations (e.g., unauth REST routes added during init).
		add_action( 'plugins_loaded', array( $this->sensors, 'register' ), 1 );

		// Admin UI
		if ( is_admin() ) {
			add_action( 'admin_menu', array( $this->settings, 'register_menu' ) );
			add_action( 'admin_init', array( $this->settings, 'register_settings' ) );
		}
	}

	/**
	 * On activation: emit activation event, create log directory,
	 * record baseline file hash of wp-config.php.
	 */
	public function activate(): void {
		$log_dir = $this->emitter->get_log_dir();
		if ( ! is_dir( $log_dir ) ) {
			wp_mkdir_p( $log_dir );
		}

		// Baseline wp-config.php hash for FIM sensor
		$wp_config = ABSPATH . 'wp-config.php';
		if ( file_exists( $wp_config ) ) {
			update_option(
				'amoskys_aegis_wpconfig_hash',
				hash_file( 'sha256', $wp_config )
			);
			update_option(
				'amoskys_aegis_wpconfig_size',
				filesize( $wp_config )
			);
		}

		$this->emitter->emit(
			'aegis.lifecycle.activated',
			array(
				'version' => AMOSKYS_AEGIS_VERSION,
				'site_url' => get_site_url(),
				'wp_version' => get_bloginfo( 'version' ),
				'php_version' => PHP_VERSION,
			),
			'info'
		);
	}

	public function deactivate(): void {
		$this->emitter->emit(
			'aegis.lifecycle.deactivated',
			array(
				'version' => AMOSKYS_AEGIS_VERSION,
				'site_url' => get_site_url(),
			),
			'warn'
		);
	}

	public function get_emitter(): Amoskys_Aegis_Emitter {
		return $this->emitter;
	}
}

// Bootstrap
Amoskys_Aegis::instance();
