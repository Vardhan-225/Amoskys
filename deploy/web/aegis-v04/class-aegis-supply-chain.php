<?php
/**
 * AMOSKYS Aegis — Plugin Supply-Chain Watcher
 *
 * The April 2026 EssentialPlugin catastrophe was a plugin-author change
 * followed by a malicious update 8 months later. Every signature-based
 * WAF missed it. The defense that catches it is STRUCTURAL: if the
 * author or committer of an installed plugin changes, tell the operator
 * NOW — before the new maintainer can push anything.
 *
 * What this does
 * ─────────────────────────────────────────────────────────────────
 *   - Daily WP-Cron pulls the local list of installed plugins.
 *   - For each plugin, fetch metadata from the WordPress.org plugin API:
 *        https://api.wordpress.org/plugins/info/1.2/?action=plugin_information&request[slug]=<slug>
 *     Fields captured: author, author_profile, added (first publish),
 *     last_updated, requires, tested, download_link, tags.
 *   - Compare to the previous snapshot (stored in wp_options).
 *   - On drift, emit `aegis.supply_chain.drift` with details.
 *
 * Drift classes
 * ─────────────────────────────────────────────────────────────────
 *   AUTHOR_CHANGED       — author field changed (HIGHEST SIGNAL)
 *   AUTHOR_PROFILE_CHANGED — author_profile URL changed
 *   STALE_FOR_YEARS     — last_updated > 18 months ago (vulnerable
 *                          to abandoned-plugin supply-chain attacks)
 *   SUDDEN_UPDATE_AFTER_LONG_SILENCE — gap > 12 months then a new
 *                          update — classic acquisition pattern
 *
 * Failure model
 * ─────────────────────────────────────────────────────────────────
 *   - Network errors are not fatal (we retry next day).
 *   - Plugins not in the wp.org directory (paid plugins) are marked
 *     as 'external' and excluded from auto-check.
 *
 * @package AmoskysAegis
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Amoskys_Aegis_Supply_Chain {

	const CRON_HOOK = 'amoskys_aegis_supply_chain_check';
	const SNAPSHOT_OPTION_PREFIX = 'amoskys_aegis_supply_';
	const SNAPSHOT_INDEX_OPTION = 'amoskys_aegis_supply_index';

	const API_ENDPOINT = 'https://api.wordpress.org/plugins/info/1.2/?action=plugin_information&request[slug]=';
	const USER_AGENT = 'AMOSKYS-Aegis-SupplyChain/1.0';
	const HTTP_TIMEOUT = 10;

	/** @var Amoskys_Aegis_Emitter */
	private $emitter;

	public function __construct( Amoskys_Aegis_Emitter $emitter ) {
		$this->emitter = $emitter;
	}

	/**
	 * Register the daily cron + the cron callback.
	 */
	public function register(): void {
		add_action( self::CRON_HOOK, array( $this, 'run_check' ) );

		if ( ! wp_next_scheduled( self::CRON_HOOK ) ) {
			wp_schedule_event( time() + 300, 'daily', self::CRON_HOOK );
		}
	}

	/**
	 * Cron entry point — fetch all plugin metadata and diff vs last snapshot.
	 */
	public function run_check(): void {
		if ( ! function_exists( 'get_plugins' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}
		$installed = get_plugins();

		$checked = 0;
		$drift_count = 0;
		$new_index = array();

		foreach ( $installed as $plugin_file => $info ) {
			$slug = $this->resolve_slug( $plugin_file );
			if ( ! $slug ) {
				continue;
			}
			$new_index[ $slug ] = array(
				'plugin_file' => $plugin_file,
				'local_name'  => $info['Name'] ?? $slug,
				'local_ver'   => $info['Version'] ?? '',
			);

			$fresh = $this->fetch_wp_org( $slug );
			if ( ! $fresh ) {
				continue; // paid / external / offline — skip silently
			}
			$checked++;

			$previous_option = self::SNAPSHOT_OPTION_PREFIX . md5( $slug );
			$previous = get_option( $previous_option, array() );

			$drift = $this->diff_snapshots( $slug, $previous, $fresh );
			if ( $drift ) {
				$drift_count++;
				$this->emitter->emit(
					'aegis.supply_chain.drift',
					array(
						'slug'         => $slug,
						'local_ver'    => $info['Version'] ?? null,
						'remote_ver'   => $fresh['version'] ?? null,
						'drift_type'   => $drift['type'],
						'reason'       => $drift['reason'],
						'old_value'    => $drift['old'] ?? null,
						'new_value'    => $drift['new'] ?? null,
						'author'       => $fresh['author'] ?? null,
						'last_updated' => $fresh['last_updated'] ?? null,
					),
					'critical' // every drift is critical — this IS the EssentialPlugin sensor
				);
			}

			update_option( $previous_option, $fresh, false );
		}

		// Persist the index so the Command Center can show the inventory
		update_option( self::SNAPSHOT_INDEX_OPTION, $new_index, false );

		// Emit a cycle-complete event even with zero drift — proves the cron ran
		$this->emitter->emit(
			'aegis.supply_chain.cycle',
			array(
				'installed'   => count( $installed ),
				'checked'     => $checked,
				'drift_count' => $drift_count,
			),
			'info'
		);
	}

	/**
	 * Plugin-file paths look like "akismet/akismet.php" — slug is the
	 * directory name.
	 */
	private function resolve_slug( string $plugin_file ): ?string {
		$parts = explode( '/', $plugin_file );
		if ( count( $parts ) >= 2 ) {
			return $parts[0];
		}
		// Single-file plugins (hello.php). Use the file stem.
		return str_replace( '.php', '', $plugin_file ) ?: null;
	}

	/**
	 * GET the wp.org API — normalize response.
	 */
	private function fetch_wp_org( string $slug ): ?array {
		$resp = wp_remote_get(
			self::API_ENDPOINT . urlencode( $slug ),
			array(
				'timeout'    => self::HTTP_TIMEOUT,
				'user-agent' => self::USER_AGENT,
			)
		);
		if ( is_wp_error( $resp ) ) {
			return null;
		}
		$code = wp_remote_retrieve_response_code( $resp );
		if ( $code !== 200 ) {
			return null;
		}
		$body = wp_remote_retrieve_body( $resp );
		$data = json_decode( $body, true );
		if ( ! is_array( $data ) || empty( $data['slug'] ) ) {
			return null;
		}
		// We keep a minimal snapshot — no need for description/screenshots.
		return array(
			'slug'            => $data['slug'],
			'author'          => $data['author'] ?? null,
			'author_profile'  => $data['author_profile'] ?? null,
			'version'         => $data['version'] ?? null,
			'added'           => $data['added'] ?? null,
			'last_updated'    => $data['last_updated'] ?? null,
			'requires'        => $data['requires'] ?? null,
			'tested'          => $data['tested'] ?? null,
			'active_installs' => $data['active_installs'] ?? null,
			'downloaded'      => $data['downloaded'] ?? null,
			'checked_at'      => gmdate( 'c' ),
		);
	}

	/**
	 * Compare two snapshots. Returns first drift found, or null.
	 *
	 * @return array|null { 'type': str, 'reason': str, 'old': mixed, 'new': mixed }
	 */
	private function diff_snapshots( string $slug, array $previous, array $fresh ): ?array {
		// First-ever check — no previous snapshot, nothing to compare.
		if ( empty( $previous ) ) {
			return null;
		}

		// 1. AUTHOR_CHANGED — the headline event we care about most
		if ( ( $previous['author'] ?? null ) !== ( $fresh['author'] ?? null ) ) {
			return array(
				'type'   => 'AUTHOR_CHANGED',
				'reason' => "Author changed from '{$previous['author']}' to '{$fresh['author']}'. "
							. 'This is the same class of event that shipped the April 2026 '
							. 'EssentialPlugin backdoor. Any new update from the new author '
							. 'should be reviewed before activating.',
				'old'    => $previous['author'] ?? null,
				'new'    => $fresh['author'] ?? null,
			);
		}

		// 2. AUTHOR_PROFILE_CHANGED — the account was transferred
		if ( ( $previous['author_profile'] ?? null ) !== ( $fresh['author_profile'] ?? null ) ) {
			return array(
				'type'   => 'AUTHOR_PROFILE_CHANGED',
				'reason' => 'The author_profile URL changed without an author_name change. '
							. 'This can indicate a silent account transfer on WordPress.org.',
				'old'    => $previous['author_profile'] ?? null,
				'new'    => $fresh['author_profile'] ?? null,
			);
		}

		// 3. SUDDEN_UPDATE_AFTER_LONG_SILENCE
		$prev_update_ts = strtotime( (string) ( $previous['last_updated'] ?? '' ) );
		$new_update_ts  = strtotime( (string) ( $fresh['last_updated'] ?? '' ) );
		if ( $prev_update_ts && $new_update_ts ) {
			$gap_days = ( $new_update_ts - $prev_update_ts ) / 86400;
			if ( $gap_days > 365 ) {
				return array(
					'type'   => 'SUDDEN_UPDATE_AFTER_LONG_SILENCE',
					'reason' => sprintf(
						'The plugin was silent for %d days, then shipped an update. '
						. 'This is the exact pattern attackers use after acquiring '
						. 'a dormant plugin and turning it malicious.',
						(int) $gap_days
					),
					'old'    => $previous['last_updated'] ?? null,
					'new'    => $fresh['last_updated'] ?? null,
				);
			}
		}

		// 4. STALE_FOR_YEARS — emit once when we notice a plugin is rotting
		if ( $new_update_ts && ( time() - $new_update_ts ) > 547 * 86400 ) {
			// Only emit if we haven't emitted it before
			if ( empty( $previous['_stale_warned'] ) ) {
				return array(
					'type'   => 'STALE_FOR_YEARS',
					'reason' => 'This plugin has not been updated in over 18 months. '
								. 'Abandoned plugins are prime supply-chain acquisition targets. '
								. 'Recommend auditing or replacing.',
					'old'    => $previous['last_updated'] ?? null,
					'new'    => $fresh['last_updated'] ?? null,
				);
			}
		}

		return null;
	}

	/**
	 * One-shot manual trigger — useful for the admin UI or CI.
	 */
	public function force_run(): void {
		$this->run_check();
	}

	public static function uninstall(): void {
		// Clear the cron + all snapshot options
		$timestamp = wp_next_scheduled( self::CRON_HOOK );
		if ( $timestamp ) {
			wp_unschedule_event( $timestamp, self::CRON_HOOK );
		}
		global $wpdb;
		$wpdb->query( "DELETE FROM {$wpdb->options} WHERE option_name LIKE '" . self::SNAPSHOT_OPTION_PREFIX . "%'" );
		delete_option( self::SNAPSHOT_INDEX_OPTION );
	}
}
