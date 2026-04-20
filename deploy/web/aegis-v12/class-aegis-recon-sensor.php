<?php
/**
 * AMOSKYS Aegis — Recon-Campaign Classifier (v1.2)
 *
 * The defensive pair to argos/recon/stealth.py. The offensive module
 * shows us what our 7-category stealth sweep looks like from the
 * outside; this sensor detects when somebody else is running an
 * equivalent sweep against us.
 *
 * Why a separate sensor from aegis.404.observed (v0.3)
 * ─────────────────────────────────────────────────────────────────
 * 404-observed is path-specific — it classifies ONE probe in isolation
 * (wp_config_probe, install_script_probe, etc.).  A recon campaign is
 * the META-signal: one IP hits ≥ 5 DISTINCT categories of probe within
 * a short window.  Individually benign, together it's reconnaissance.
 *
 * Categories we track (parallel to argos/recon/stealth.py)
 * ─────────────────────────────────────────────────────────────────
 *   wp_core        — /readme.html, /wp-login.php, /wp-json/, /feed
 *   dev_leaks      — /.git, /.env, /wp-config.php.bak*, /composer.json
 *   plugin_dirs    — /wp-content/plugins/SLUG/readme.txt or version
 *   infra_probes   — /phpinfo.php, /info.php, /server-status
 *   user_enum      — /?author=1, /?author=2, /wp-json/wp/v2/users
 *   admin_paths    — /wp-admin/, /xmlrpc.php, /admin/, /administrator/
 *   backups        — *.sql, *.sql.gz, *.tar.gz, /backup/
 *
 * Rule
 * ─────────────────────────────────────────────────────────────────
 * If one IP is observed hitting ≥ 5 DISTINCT categories within 10 min,
 * emit `aegis.recon.campaign` at severity HIGH, with the list of
 * categories touched.  Fire strike `recon_campaign` (threshold 1 →
 * immediate 10-min block).
 *
 * We don't count repeats within a category — hitting /.git/config ten
 * times is one "dev_leaks" touch. Keeps false-positive rate low for
 * scanners that hammer a single path.
 *
 * State storage
 * ─────────────────────────────────────────────────────────────────
 * Per-IP bitmap stored in a WordPress transient:
 *   amoskys_recon_<md5(ip)>  →  serialized {category_mask, first_ts, paths[]}
 * TTL 10 min auto-expires the campaign window.
 *
 * @package AmoskysAegis
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Amoskys_Aegis_Recon_Sensor {

	/** @var Amoskys_Aegis_Emitter */
	private $emitter;

	const STRIKE_RULE     = 'recon_campaign';
	const WINDOW_SEC      = 600;   // 10 minutes
	const CATEGORY_THRESHOLD = 5;  // distinct categories → campaign

	/**
	 * Path → category map. Order matters: the first match wins.
	 * Values are { pattern, category }.
	 */
	const PATH_CATEGORIES = array(
		// wp_core
		array( 'pattern' => '#/readme\.html$#i',             'category' => 'wp_core' ),
		array( 'pattern' => '#/wp-login\.php$#i',            'category' => 'wp_core' ),
		array( 'pattern' => '#/wp-json/?$#i',                'category' => 'wp_core' ),
		array( 'pattern' => '#/feed/?$#i',                   'category' => 'wp_core' ),
		array( 'pattern' => '#/sitemap\.xml$#i',             'category' => 'wp_core' ),

		// dev_leaks
		array( 'pattern' => '#/\.git/#',                     'category' => 'dev_leaks' ),
		array( 'pattern' => '#/\.env(\.[a-z]+)?$#i',         'category' => 'dev_leaks' ),
		array( 'pattern' => '#/wp-config\.php(\.bak|~|\.save|\.old)$#i', 'category' => 'dev_leaks' ),
		array( 'pattern' => '#/composer\.(json|lock)$#i',    'category' => 'dev_leaks' ),
		array( 'pattern' => '#/package\.json$#i',            'category' => 'dev_leaks' ),
		array( 'pattern' => '#/\.DS_Store$#',                'category' => 'dev_leaks' ),
		array( 'pattern' => '#/\.idea/#',                    'category' => 'dev_leaks' ),
		array( 'pattern' => '#/README\.md$#i',               'category' => 'dev_leaks' ),

		// plugin_dirs
		array( 'pattern' => '#/wp-content/plugins/[^/]+/readme\.(txt|md)$#i', 'category' => 'plugin_dirs' ),

		// infra_probes
		array( 'pattern' => '#/(phpinfo|info|test|php-info)\.php$#i', 'category' => 'infra_probes' ),
		array( 'pattern' => '#/server-status$#i',            'category' => 'infra_probes' ),
		array( 'pattern' => '#/server-info$#i',              'category' => 'infra_probes' ),

		// user_enum
		array( 'pattern' => '#\?author=\d+#',                'category' => 'user_enum' ),
		array( 'pattern' => '#/wp-json/wp/v2/users#',        'category' => 'user_enum' ),

		// admin_paths (attacker probing for non-WP admin panels)
		array( 'pattern' => '#/(administrator|admin)/?$#i',  'category' => 'admin_paths' ),
		array( 'pattern' => '#/xmlrpc\.php#',                'category' => 'admin_paths' ),
		array( 'pattern' => '#/phpmyadmin#i',                'category' => 'admin_paths' ),

		// backups
		array( 'pattern' => '#\.(sql|sql\.gz|sql\.bz2)$#i',  'category' => 'backups' ),
		array( 'pattern' => '#\.(tar\.gz|tgz|zip|7z)$#i',    'category' => 'backups' ),
		array( 'pattern' => '#/backup/?#i',                  'category' => 'backups' ),
	);

	public function __construct( Amoskys_Aegis_Emitter $emitter ) {
		$this->emitter = $emitter;
	}

	public function register(): void {
		// init @ -90 — after the POI+CSRF+SSRF sensors, before the plugin's
		// own routing.
		add_action( 'init', array( $this, 'inspect_request' ), -90 );
	}

	public function inspect_request(): void {
		// Skip WP-CLI and cron.
		if ( ( defined( 'WP_CLI' ) && WP_CLI )
		  || ( defined( 'DOING_CRON' ) && DOING_CRON ) ) {
			return;
		}

		$uri = isset( $_SERVER['REQUEST_URI'] ) ? (string) $_SERVER['REQUEST_URI'] : '';
		if ( $uri === '' ) {
			return;
		}

		$category = $this->classify_path( $uri );
		if ( $category === null ) {
			return;
		}

		$ip = $this->get_ip();
		if ( ! $ip ) {
			return;
		}

		// Fetch / initialize per-IP record.
		$key  = 'amoskys_recon_' . md5( $ip );
		$rec  = get_transient( $key );
		if ( ! is_array( $rec ) ) {
			$rec = array(
				'first_ts'   => time(),
				'categories' => array(),
				'paths'      => array(),
			);
		}
		// Add the category (dedup) and keep a rolling 20-path tail for evidence.
		if ( ! in_array( $category, $rec['categories'], true ) ) {
			$rec['categories'][] = $category;
		}
		$rec['paths'][] = substr( $uri, 0, 150 );
		if ( count( $rec['paths'] ) > 20 ) {
			$rec['paths'] = array_slice( $rec['paths'], -20 );
		}
		set_transient( $key, $rec, self::WINDOW_SEC );

		// Have we tripped the threshold?
		if ( count( $rec['categories'] ) >= self::CATEGORY_THRESHOLD
		  && empty( $rec['emitted'] ) ) {
			// Mark as emitted so we don't spam on every subsequent probe.
			$rec['emitted'] = true;
			set_transient( $key, $rec, self::WINDOW_SEC );

			$this->emitter->emit(
				'aegis.recon.campaign',
				array(
					'ip'              => $ip,
					'categories'      => $rec['categories'],
					'category_count'  => count( $rec['categories'] ),
					'paths'           => $rec['paths'],
					'window_started'  => $rec['first_ts'],
					'window_duration_s' => time() - (int) $rec['first_ts'],
				),
				'high'
			);
			do_action( 'amoskys_aegis_strike', self::STRIKE_RULE, $ip );
		}
	}

	/**
	 * Match a request URI against our category table. Returns the matched
	 * category name, or null if the URI is uninteresting.
	 */
	private function classify_path( string $uri ) {
		foreach ( self::PATH_CATEGORIES as $entry ) {
			if ( @preg_match( $entry['pattern'], $uri ) ) {
				return $entry['category'];
			}
		}
		return null;
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
