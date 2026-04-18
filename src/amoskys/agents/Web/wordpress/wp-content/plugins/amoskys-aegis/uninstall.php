<?php
/**
 * AMOSKYS Aegis — uninstall.
 *
 * Runs when the plugin is deleted via the WP admin. Cleans up options
 * so a fresh install starts fresh. Logs are intentionally NOT deleted —
 * forensic preservation principle.
 *
 * @package AmoskysAegis
 */

if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) ) {
	exit;
}

$options = array(
	'amoskys_aegis_remote_url',
	'amoskys_aegis_api_key',
	'amoskys_aegis_trust_proxy',
	'amoskys_aegis_site_id',
	'amoskys_aegis_wpconfig_hash',
	'amoskys_aegis_wpconfig_size',
	'amoskys_aegis_prev_sig',
);

foreach ( $options as $opt ) {
	delete_option( $opt );
	delete_site_option( $opt );
}
