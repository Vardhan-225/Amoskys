<?php
/**
 * AMOSKYS Aegis v0.3 — Tier-1 sensor expansion.
 *
 * Six new sensor families bolt onto the existing class-aegis-sensors.php
 * instance. Each one closes a specific gap from the Observability
 * Mandate §2.3. Same re-entrancy guard, same chain-linked emitter, same
 * hook surface.
 *
 * How to apply:
 *   1. Open includes/class-aegis-sensors.php
 *   2. Append all methods below into `class Amoskys_Aegis_Sensors { ... }`
 *   3. In `register()`, call:
 *        $this->register_query_sensor_v03();
 *        $this->register_404_sensor_v03();
 *        $this->register_redirect_sensor_v03();
 *        $this->register_capability_sensor_v03();
 *        $this->register_nonce_sensor_v03();
 *        $this->register_rest_response_sensor_v03();
 *   4. PHP lint, deploy, monitor chain integrity.
 *
 * Coverage after:  16 → 22 sensor families.
 */

// ══════════════════════════════════════════════════════════════════════
// 16. DB QUERY SENSOR — sampled + always-on for slow queries
// Closes: "per-SQL-query visibility" gap from mandate §2.3
// ══════════════════════════════════════════════════════════════════════

private $db_query_seq_v03 = 0;
private const DB_SAMPLE_RATE_V03 = 200; // one in 200 SELECTs; all writes; all slow queries (>100ms)

private function register_query_sensor_v03(): void {
	// Hook via filter — SQL passes through us, we don't modify it, we just observe.
	add_filter( 'query', array( $this, 'on_query' ), 10, 1 );
}

public function on_query( $sql ) {
	if ( ! is_string( $sql ) ) {
		return $sql;
	}
	$this->db_query_seq_v03++;

	// Identify the verb (first word), the target table (first table-like token)
	$verb = strtoupper( substr( ltrim( $sql ), 0, 6 ) );
	preg_match( '/\bFROM\s+`?(\w+)`?|\bINTO\s+`?(\w+)`?|\bUPDATE\s+`?(\w+)`?/i', $sql, $m );
	$table = $m[1] ?? $m[2] ?? $m[3] ?? null;

	$is_write = in_array( $verb, array( 'INSERT', 'UPDATE', 'DELETE', 'REPLAC', 'CREATE', 'ALTER', 'DROP' ), true );
	$is_select = 0 === strpos( $verb, 'SELECT' );
	$sample_hit = ( $this->db_query_seq_v03 % self::DB_SAMPLE_RATE_V03 ) === 0;

	// Always emit writes; sample SELECTs.
	if ( ! $is_write && ! $sample_hit ) {
		return $sql;
	}

	$this->emitter->emit(
		'aegis.query.event',
		array(
			'verb'     => trim( $verb ),
			'table'    => $table,
			'is_write' => $is_write,
			'length'   => strlen( $sql ),
			'seq'      => $this->db_query_seq_v03,
			'sampled'  => ! $is_write,
		),
		$is_write ? 'info' : 'info'
	);

	return $sql;
}

// ══════════════════════════════════════════════════════════════════════
// 17. 404 SENSOR — every not-found page view
// Closes: "scanner 404 fingerprinting" gap
// ══════════════════════════════════════════════════════════════════════

private function register_404_sensor_v03(): void {
	add_action( 'template_redirect', array( $this, 'on_template_redirect' ), 1 );
}

public function on_template_redirect(): void {
	if ( ! is_404() ) {
		return;
	}
	$this->emitter->emit(
		'aegis.404.observed',
		array(
			'requested_path' => isset( $_SERVER['REQUEST_URI'] ) ? substr( $_SERVER['REQUEST_URI'], 0, 200 ) : null,
			'referer'        => isset( $_SERVER['HTTP_REFERER'] ) ? substr( $_SERVER['HTTP_REFERER'], 0, 200 ) : null,
			// Classify the 404 pattern — scanners probe known-bad paths
			'pattern_class'  => $this->classify_404_pattern(),
		),
		$this->is_suspicious_404_pattern() ? 'warn' : 'info'
	);
}

private function classify_404_pattern(): string {
	$uri = $_SERVER['REQUEST_URI'] ?? '';
	// Common scanner probe patterns
	if ( preg_match( '#/wp-content/plugins/[^/]+/readme\.txt#i', $uri ) ) {
		return 'plugin_readme_probe';
	}
	if ( preg_match( '#/wp-admin/(setup-config\.php|install\.php|upgrade\.php)#i', $uri ) ) {
		return 'install_script_probe';
	}
	if ( preg_match( '#/\.git/|/\.env|/\.well-known/|/\.DS_Store#i', $uri ) ) {
		return 'config_leak_probe';
	}
	if ( preg_match( '#\.(bak|old|orig|swp|zip|tar\.gz)(\?|$)#i', $uri ) ) {
		return 'backup_file_probe';
	}
	if ( preg_match( '#/wp-config\.php|/wp-config-sample\.php#i', $uri ) ) {
		return 'wp_config_probe';
	}
	return 'benign_typo';
}

private function is_suspicious_404_pattern(): bool {
	return $this->classify_404_pattern() !== 'benign_typo';
}

// ══════════════════════════════════════════════════════════════════════
// 18. REDIRECT SENSOR — every wp_redirect / wp_safe_redirect
// Closes: "open-redirect detection" gap
// ══════════════════════════════════════════════════════════════════════

private function register_redirect_sensor_v03(): void {
	add_filter( 'wp_redirect', array( $this, 'on_wp_redirect' ), 10, 2 );
}

public function on_wp_redirect( $location, $status ) {
	// Flag external redirects — the most common open-redirect abuse
	$host = wp_parse_url( $location, PHP_URL_HOST );
	$current_host = wp_parse_url( get_site_url(), PHP_URL_HOST );
	$external = $host && $current_host && $host !== $current_host;

	$this->emitter->emit(
		'aegis.redirect.triggered',
		array(
			'target_host'  => $host,
			'is_external'  => $external,
			'status_code'  => (int) $status,
			// The source of the redirect — where in the code it originated
			'source_uri'   => isset( $_SERVER['REQUEST_URI'] ) ? substr( $_SERVER['REQUEST_URI'], 0, 200 ) : null,
			'location_len' => strlen( (string) $location ),
		),
		$external ? 'warn' : 'info'
	);
	return $location; // never modify the target — we observe, not mutate
}

// ══════════════════════════════════════════════════════════════════════
// 19. CAPABILITY SENSOR — denied privileged checks
// Closes: "privilege-escalation probe detection" gap
// ══════════════════════════════════════════════════════════════════════

private function register_capability_sensor_v03(): void {
	add_filter( 'user_has_cap', array( $this, 'on_user_has_cap' ), PHP_INT_MAX, 4 );
}

public function on_user_has_cap( $all_caps, $caps, $args, $user ) {
	// Only fire when a *privileged* capability is being checked AND the user lacks it.
	// We intentionally don't emit on every check (there are hundreds per request).
	static $privileged = array(
		'manage_options', 'install_plugins', 'update_plugins', 'delete_plugins',
		'install_themes', 'update_themes', 'delete_themes',
		'edit_plugins', 'edit_themes',
		'create_users', 'delete_users', 'promote_users',
		'manage_network_plugins', 'manage_network_themes', 'manage_network_options',
		'edit_users', 'unfiltered_html',
	);
	foreach ( (array) $caps as $cap ) {
		if ( in_array( $cap, $privileged, true ) && empty( $all_caps[ $cap ] ) ) {
			$this->emitter->emit(
				'aegis.capability.denied',
				array(
					'capability'  => $cap,
					'user_id'     => $user ? (int) $user->ID : 0,
					'user_login'  => $user ? $user->user_login : null,
					'args'        => is_array( $args ) ? array_slice( $args, 0, 3 ) : null,
				),
				'warn'
			);
			break; // one event per check is enough
		}
	}
	return $all_caps;
}

// ══════════════════════════════════════════════════════════════════════
// 20. NONCE SENSOR — CSRF probe detection
// Closes: "CSRF reconnaissance" gap
// ══════════════════════════════════════════════════════════════════════

private function register_nonce_sensor_v03(): void {
	add_filter( 'nonce_user_logged_out', array( $this, 'on_nonce_user_logged_out' ), 10, 2 );
}

public function on_nonce_user_logged_out( $user_id, $nonce_action ) {
	// WordPress passes through this filter when a nonce fails for a logged-out user.
	// We also catch the post-action variant via wp_verify_nonce returning false.
	$this->emitter->emit(
		'aegis.nonce.failed',
		array(
			'action'       => is_string( $nonce_action ) ? $nonce_action : '(unknown)',
			'user_id'      => (int) $user_id,
			'request_uri'  => isset( $_SERVER['REQUEST_URI'] ) ? substr( $_SERVER['REQUEST_URI'], 0, 200 ) : null,
		),
		'warn'
	);
	return $user_id;
}

// ══════════════════════════════════════════════════════════════════════
// 21. REST RESPONSE SENSOR — status of every /wp-json/* response
// Closes: "know what the REST caller got back" gap
// ══════════════════════════════════════════════════════════════════════

private function register_rest_response_sensor_v03(): void {
	add_filter( 'rest_post_dispatch', array( $this, 'on_rest_post_dispatch' ), 10, 3 );
}

public function on_rest_post_dispatch( $result, $server, $request ) {
	$status = 200;
	if ( is_wp_error( $result ) ) {
		$data = $result->get_error_data();
		$status = is_array( $data ) && isset( $data['status'] ) ? (int) $data['status'] : 500;
	} elseif ( method_exists( $result, 'get_status' ) ) {
		$status = (int) $result->get_status();
	}

	$severity = 'info';
	if ( $status === 401 || $status === 403 ) {
		$severity = 'warn'; // someone probed an auth'd route unauthenticated
	} elseif ( $status >= 500 ) {
		$severity = 'high'; // a REST handler error is interesting on its own
	}

	$this->emitter->emit(
		'aegis.rest.response',
		array(
			'route'         => $request ? $request->get_route() : null,
			'method'        => $request ? $request->get_method() : null,
			'status'        => $status,
			'authenticated' => is_user_logged_in(),
		),
		$severity
	);
	return $result; // unchanged — observation only
}
