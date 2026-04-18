<?php
/**
 * AMOSKYS Aegis — Admin Settings Page
 *
 * Minimal settings surface:
 *   - Remote AMOSKYS ingest URL
 *   - API key for that endpoint
 *   - Trust proxy headers (for sites behind Cloudflare etc.)
 *   - Site identifier (read-only; rotatable)
 *
 * Deliberately simple. No fancy UI framework, no AJAX — just the
 * Settings API. Admin surface is itself an attack surface; smaller is safer.
 *
 * @package AmoskysAegis
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Amoskys_Aegis_Settings {

	const OPTION_GROUP = 'amoskys_aegis_settings';
	const OPTION_PAGE  = 'amoskys-aegis';

	public function register_menu(): void {
		add_options_page(
			'AMOSKYS Aegis',
			'AMOSKYS Aegis',
			'manage_options',
			self::OPTION_PAGE,
			array( $this, 'render_page' )
		);
	}

	public function register_settings(): void {
		register_setting( self::OPTION_GROUP, 'amoskys_aegis_remote_url', array(
			'type' => 'string',
			'sanitize_callback' => 'esc_url_raw',
			'default' => '',
		) );
		register_setting( self::OPTION_GROUP, 'amoskys_aegis_api_key', array(
			'type' => 'string',
			'sanitize_callback' => 'sanitize_text_field',
			'default' => '',
		) );
		register_setting( self::OPTION_GROUP, 'amoskys_aegis_trust_proxy', array(
			'type' => 'boolean',
			'sanitize_callback' => 'rest_sanitize_boolean',
			'default' => false,
		) );

		add_settings_section(
			'amoskys_aegis_section_brain',
			'AMOSKYS Brain Connection',
			function () {
				echo '<p>Where Aegis ships its events. Leave blank to only write events to the local log.</p>';
			},
			self::OPTION_PAGE
		);

		add_settings_field(
			'amoskys_aegis_remote_url',
			'Ingest URL',
			array( $this, 'render_field_url' ),
			self::OPTION_PAGE,
			'amoskys_aegis_section_brain'
		);

		add_settings_field(
			'amoskys_aegis_api_key',
			'API Key',
			array( $this, 'render_field_api_key' ),
			self::OPTION_PAGE,
			'amoskys_aegis_section_brain'
		);

		add_settings_field(
			'amoskys_aegis_trust_proxy',
			'Trust Proxy Headers',
			array( $this, 'render_field_trust_proxy' ),
			self::OPTION_PAGE,
			'amoskys_aegis_section_brain'
		);
	}

	public function render_field_url(): void {
		$val = get_option( 'amoskys_aegis_remote_url', '' );
		printf(
			'<input type="url" name="amoskys_aegis_remote_url" value="%s" class="regular-text" placeholder="https://ops.amoskys.com/v1/web/events" />',
			esc_attr( $val )
		);
	}

	public function render_field_api_key(): void {
		$val = get_option( 'amoskys_aegis_api_key', '' );
		$masked = $val ? substr( $val, 0, 4 ) . str_repeat( '•', max( 0, strlen( $val ) - 8 ) ) . substr( $val, -4 ) : '';
		printf(
			'<input type="password" name="amoskys_aegis_api_key" value="%s" class="regular-text" autocomplete="new-password" />',
			esc_attr( $val )
		);
		if ( $val ) {
			printf( '<p class="description">Current (masked): <code>%s</code></p>', esc_html( $masked ) );
		}
	}

	public function render_field_trust_proxy(): void {
		$val = (bool) get_option( 'amoskys_aegis_trust_proxy', false );
		printf(
			'<label><input type="checkbox" name="amoskys_aegis_trust_proxy" value="1" %s /> Trust X-Forwarded-For / CF-Connecting-IP</label>',
			checked( $val, true, false )
		);
		echo '<p class="description">Enable only if your site is behind a trusted reverse proxy (Cloudflare, AWS ALB, etc.). Off by default because misconfigured trust == IP spoofing.</p>';
	}

	public function render_page(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}

		// Current site_id (read-only informational)
		$site_id = get_option( 'amoskys_aegis_site_id', '(not yet generated)' );
		$log_dir = wp_upload_dir()['basedir'] . '/amoskys-aegis';
		$log_file = $log_dir . '/events.jsonl';
		$log_exists = file_exists( $log_file );
		$log_size = $log_exists ? size_format( filesize( $log_file ) ) : '(none)';
		$log_lines = 0;
		if ( $log_exists ) {
			$fh = @fopen( $log_file, 'r' );
			if ( $fh ) {
				while ( ! feof( $fh ) ) {
					if ( fgets( $fh ) !== false ) {
						$log_lines++;
					}
				}
				fclose( $fh );
			}
		}

		?>
		<div class="wrap">
			<h1>AMOSKYS Aegis — Settings</h1>
			<p>Version <?php echo esc_html( AMOSKYS_AEGIS_VERSION ); ?> &mdash; Defensive sensor for WordPress. Ships events to the AMOSKYS brain for correlation.</p>

			<h2>Site Identity</h2>
			<table class="form-table" role="presentation">
				<tbody>
					<tr>
						<th scope="row">Site ID</th>
						<td><code><?php echo esc_html( $site_id ); ?></code> <span class="description">(stable per-site identifier used by the AMOSKYS fleet)</span></td>
					</tr>
					<tr>
						<th scope="row">Log File</th>
						<td><code><?php echo esc_html( $log_file ); ?></code><br>
						<span class="description">Size: <?php echo esc_html( $log_size ); ?> · Events: <?php echo esc_html( (string) $log_lines ); ?></span></td>
					</tr>
				</tbody>
			</table>

			<h2>Configuration</h2>
			<form method="post" action="options.php">
				<?php
				settings_fields( self::OPTION_GROUP );
				do_settings_sections( self::OPTION_PAGE );
				submit_button();
				?>
			</form>
		</div>
		<?php
	}
}
