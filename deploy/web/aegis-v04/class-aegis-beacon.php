<?php
/**
 * AMOSKYS Aegis — Browser Beacon (Tier 1.5)
 *
 * Captures admin-page client-side events that the server never sees:
 *   - page_load            — admin opens a page
 *   - page_unload          — admin closes a page
 *   - visibility_change    — tab hidden/visible
 *   - idle                 — no activity for 2 min
 *   - click_summary        — total clicks per page (not per click)
 *   - keypress_summary     — total keypress count per page
 *   - copy / paste         — clipboard events (admin may have leaked secrets)
 *   - fetch_error          — client-side fetch/XHR failures
 *
 * Scope: admin pages only. We never inject into public-facing pages
 * because (a) the privacy surface is larger, and (b) the high-value
 * signal is admin-session behavior, not visitor behavior.
 *
 * Transport: REST endpoint `/wp-json/amoskys-aegis/v1/beacon`.
 * Auth: the current admin session (the existing WP nonce is what
 * gates access; we verify it in permission_callback).
 *
 * Batching: the JS snippet accumulates events and flushes every 30s
 * + on beforeunload via navigator.sendBeacon().
 *
 * @package AmoskysAegis
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Amoskys_Aegis_Beacon {

	/** @var Amoskys_Aegis_Emitter */
	private $emitter;

	public function __construct( Amoskys_Aegis_Emitter $emitter ) {
		$this->emitter = $emitter;
	}

	public function register(): void {
		// Inject the beacon JS into every admin page
		add_action( 'admin_enqueue_scripts', array( $this, 'enqueue_beacon' ) );
		// Register the REST endpoint that receives the batches
		add_action( 'rest_api_init', array( $this, 'register_routes' ) );
	}

	/**
	 * Inline-enqueue a minimal JS snippet into every admin page.
	 * Kept inline (no external file) so we have zero additional HTTP
	 * requests for the beacon.
	 */
	public function enqueue_beacon(): void {
		if ( ! is_admin() || ! is_user_logged_in() ) {
			return;
		}
		$current_user_id = get_current_user_id();
		$nonce = wp_create_nonce( 'wp_rest' );
		$endpoint = esc_url_raw( rest_url( 'amoskys-aegis/v1/beacon' ) );

		$js = <<<JS
(function(){
  if (window.__amoskysBeacon) return;
  window.__amoskysBeacon = true;

  var endpoint = {$this->js_string($endpoint)};
  var nonce = {$this->js_string($nonce)};
  var uid = {$current_user_id};
  var pageLoadAt = Date.now();
  var queue = [];
  var clicks = 0, keypresses = 0;
  var idleStart = null;
  var lastActivity = Date.now();
  var visibilityChanges = 0;

  function push(type, data) {
    queue.push({
      event_type: type,
      occurred_at: Date.now(),
      page_url: location.href.slice(0, 500),
      user_id: uid,
      data: data || {}
    });
    if (queue.length >= 20) flush(false);
  }

  function flush(isFinal) {
    if (!queue.length) return;
    var payload = JSON.stringify({events: queue.splice(0)});
    if (isFinal && navigator.sendBeacon) {
      // Beacon API — works even during beforeunload
      try {
        var blob = new Blob([payload], {type: 'application/json'});
        navigator.sendBeacon(endpoint + '?_wpnonce=' + encodeURIComponent(nonce), blob);
      } catch(e){}
      return;
    }
    try {
      fetch(endpoint, {
        method: 'POST',
        headers: {'Content-Type':'application/json', 'X-WP-Nonce': nonce},
        body: payload,
        keepalive: true,
        credentials: 'same-origin'
      }).catch(function(){});
    } catch(e){}
  }

  // page load
  push('page_load', {referrer: (document.referrer||'').slice(0,500)});

  // click + keypress counting
  document.addEventListener('click', function(){ clicks++; lastActivity = Date.now(); }, {passive:true, capture:true});
  document.addEventListener('keydown', function(){ keypresses++; lastActivity = Date.now(); }, {passive:true, capture:true});

  // idle detection
  setInterval(function(){
    var now = Date.now();
    if (now - lastActivity > 120000) {
      if (!idleStart) { idleStart = now; push('idle_start', {since: lastActivity}); }
    } else if (idleStart) {
      push('idle_end', {idle_ms: now - idleStart});
      idleStart = null;
    }
  }, 10000);

  // visibility
  document.addEventListener('visibilitychange', function(){
    visibilityChanges++;
    push('visibility_change', {hidden: document.hidden, count: visibilityChanges});
  });

  // clipboard (may indicate credential copy/paste)
  document.addEventListener('copy',  function(){ push('clipboard', {action:'copy'}); });
  document.addEventListener('paste', function(){ push('clipboard', {action:'paste'}); });

  // periodic flush every 30s
  setInterval(function(){
    push('heartbeat', {
      clicks: clicks,
      keypresses: keypresses,
      on_page_ms: Date.now() - pageLoadAt
    });
    clicks = 0; keypresses = 0;
    flush(false);
  }, 30000);

  // final beacon on unload
  window.addEventListener('beforeunload', function(){
    push('page_unload', {
      total_clicks: clicks,
      total_keypresses: keypresses,
      total_on_page_ms: Date.now() - pageLoadAt
    });
    flush(true);
  });
})();
JS;

		// Print inline in the admin footer
		add_action( 'admin_print_footer_scripts', function () use ( $js ) {
			echo "<script>\n" . $js . "\n</script>\n";
		} );
	}

	// Quote a string safely for inline JS
	private function js_string( $s ): string {
		return json_encode( (string) $s, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE );
	}

	/**
	 * Register the REST endpoint.
	 */
	public function register_routes(): void {
		register_rest_route(
			'amoskys-aegis/v1',
			'/beacon',
			array(
				'methods'             => 'POST',
				'callback'            => array( $this, 'handle_beacon' ),
				'permission_callback' => array( $this, 'check_permission' ),
			)
		);
	}

	public function check_permission( \WP_REST_Request $request ): bool {
		// Must be a logged-in user + must have the rest_nonce
		if ( ! is_user_logged_in() ) {
			return false;
		}
		$nonce = $request->get_header( 'X-WP-Nonce' ) ?: $request->get_param( '_wpnonce' );
		if ( ! $nonce || ! wp_verify_nonce( $nonce, 'wp_rest' ) ) {
			return false;
		}
		return true;
	}

	public function handle_beacon( \WP_REST_Request $request ): \WP_REST_Response {
		$body = $request->get_json_params();
		if ( ! is_array( $body ) || empty( $body['events'] ) || ! is_array( $body['events'] ) ) {
			return new \WP_REST_Response( array( 'accepted' => 0 ), 400 );
		}

		$accepted = 0;
		foreach ( $body['events'] as $event ) {
			if ( ! is_array( $event ) ) {
				continue;
			}
			$event_type = isset( $event['event_type'] ) ? sanitize_key( $event['event_type'] ) : '';
			if ( ! $event_type ) {
				continue;
			}

			// Severity mapping — clipboard + idle_end with long duration = warn,
			// others are info.
			$sev = 'info';
			if ( $event_type === 'clipboard' ) {
				$sev = 'warn';
			}

			$this->emitter->emit(
				'aegis.browser.' . $event_type,
				array(
					'page_url'    => isset( $event['page_url'] ) ? substr( (string) $event['page_url'], 0, 500 ) : null,
					'user_id'     => isset( $event['user_id'] ) ? (int) $event['user_id'] : null,
					'occurred_at' => isset( $event['occurred_at'] ) ? (int) $event['occurred_at'] : null,
					'data'        => is_array( $event['data'] ?? null ) ? $event['data'] : array(),
				),
				$sev
			);
			$accepted++;
		}

		return new \WP_REST_Response( array( 'accepted' => $accepted ), 200 );
	}
}
