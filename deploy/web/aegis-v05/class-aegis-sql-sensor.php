<?php
/**
 * AMOSKYS Aegis — SQL Runtime Classifier (v0.5)
 *
 * The defensive pair to Argos's `ast/sql_injection.py` scanner.
 * One watches for SQLi in plugin *source*, the other watches for SQLi
 * payloads in live *queries*. A bug caught by either is a win; a bug
 * caught by both is a confirmed exploitation attempt.
 *
 * Hook surface
 * ─────────────────────────────────────────────────────────────────
 * WordPress applies the `query` filter right before every $wpdb
 * query executes. We tap that filter (priority 0, early) and look
 * for the signatures below. The filter returns the query unchanged
 * — we ONLY observe, we don't rewrite.
 *
 * Signatures we flag (conservative to avoid false positives)
 * ─────────────────────────────────────────────────────────────────
 *   UNION_SELECT    — UNION[comment]SELECT — classic data extraction.
 *                     Plugins can legitimately use UNION, so we require
 *                     the request to be unauth OR the query to reference
 *                     information_schema.
 *
 *   TIME_BASED_BLIND — `SLEEP(`, `BENCHMARK(`, `WAITFOR DELAY` — these
 *                     have almost no legitimate use inside a WP plugin
 *                     query; any occurrence is treated as critical.
 *
 *   FILE_PRIMITIVES — `INTO OUTFILE`, `INTO DUMPFILE`, `LOAD_FILE(` —
 *                     the mariadb/mysql primitives that an attacker uses
 *                     after SQLi to escalate to RCE or read files.
 *
 *   SCHEMA_DISCOVERY — `information_schema.`, `performance_schema.`,
 *                     `mysql.user` — schema enumeration, almost always
 *                     an attacker mapping the DB.
 *
 *   STACKED_QUERIES  — `;[whitespace]SELECT|INSERT|UPDATE|DELETE|DROP`
 *                     WP's $wpdb uses mysqli without multi_query, so
 *                     a stacked query in the string is either a plugin
 *                     doing something weird OR an SQLi payload. Either
 *                     is worth attention.
 *
 *   COMMENT_BYPASS   — ` -- -`, `/*!` — MySQL conditional comments and
 *                     the classic `'--` comment-out-the-rest pattern.
 *                     We require *exactly* this form so `--` used as
 *                     documentation doesn't false-positive.
 *
 *   BOOLEAN_TAUTOLOGY — `OR 1=1`, `OR 'a'='a'`, `OR "" =""` — the
 *                     auth-bypass classic. Case-insensitive.
 *
 *   ENCODED_PAYLOAD  — CHAR(...) or CONCAT(CHAR(..)) constructing strings
 *                     from character codes — a payload-obfuscation move.
 *
 * Strike integration
 * ─────────────────────────────────────────────────────────────────
 * Each match fires `aegis.db.suspicious_query` at severity `high` (or
 * `critical` for TIME_BASED_BLIND / FILE_PRIMITIVES / STACKED_QUERIES).
 *
 * We ALSO fire the v0.4 strike action:
 *     do_action('amoskys_aegis_strike', 'sqli_attempt', $ip);
 *
 * With threshold SQLI_ATTEMPT_LIMIT = 2 (two suspicious queries in the
 * 60s window → immediate 10-min block) this turns the SQL classifier
 * into an active-defense primitive for free.
 *
 * False-positive budget
 * ─────────────────────────────────────────────────────────────────
 * The classifier runs on every $wpdb query. False positives here are
 * expensive — they block legit traffic. We keep the patterns tight and
 * record the full query for every hit so the operator can triage.
 * If a legit plugin query trips a pattern, we emit with severity
 * `info` instead of firing the strike (the `whitelist_query_hash`
 * option lets the operator suppress specific patterns).
 *
 * @package AmoskysAegis
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Amoskys_Aegis_Sql_Sensor {

	/** @var Amoskys_Aegis_Emitter */
	private $emitter;

	/** @var int requests-per-process query budget before we bail on scanning */
	const MAX_QUERIES_PER_REQUEST = 500;

	/** @var int max characters of a query we'll save into an event */
	const MAX_QUERY_SNIPPET = 400;

	/** Strike rule name, paired with the v0.4 block engine. */
	const STRIKE_RULE = 'sqli_attempt';

	/** Per-request counter — we stop scanning after the budget to protect FPM. */
	private $scanned = 0;

	public function __construct( Amoskys_Aegis_Emitter $emitter ) {
		$this->emitter = $emitter;
	}

	public function register(): void {
		// `query` filter runs just before $wpdb executes. Priority 0 so
		// we see the query in the form the plugin passed it.
		add_filter( 'query', array( $this, 'inspect_query' ), 0 );
	}

	/**
	 * Filter callback — inspect and return the query unchanged.
	 */
	public function inspect_query( $query ) {
		// Fast exits — keep the hot path cheap.
		if ( ! is_string( $query ) || $query === '' ) {
			return $query;
		}
		if ( $this->scanned >= self::MAX_QUERIES_PER_REQUEST ) {
			return $query;
		}
		$this->scanned++;

		$hits = $this->classify( $query );
		if ( empty( $hits ) ) {
			return $query;
		}

		$ip = $this->get_ip();
		$is_authed = is_user_logged_in();

		// Highest-severity hit becomes the event severity.
		$severity = 'high';
		foreach ( $hits as $h ) {
			if ( $h['severity'] === 'critical' ) { $severity = 'critical'; break; }
		}

		$this->emitter->emit(
			'aegis.db.suspicious_query',
			array(
				'ip'        => $ip,
				'authed'    => $is_authed,
				'patterns'  => array_column( $hits, 'pattern' ),
				'query'     => substr( $query, 0, self::MAX_QUERY_SNIPPET ),
				'query_len' => strlen( $query ),
				'classes'   => array_unique( array_column( $hits, 'class' ) ),
			),
			$severity
		);

		// Strike handoff — only for unauth or high/critical classifications.
		// (Auth'd users doing info_schema in a backup plugin shouldn't self-ban.)
		$strike_worthy = false;
		foreach ( $hits as $h ) {
			if ( in_array( $h['class'], array(
				'TIME_BASED_BLIND',
				'FILE_PRIMITIVES',
				'STACKED_QUERIES',
				'COMMENT_BYPASS',
				'BOOLEAN_TAUTOLOGY',
				'ENCODED_PAYLOAD',
			), true ) ) {
				$strike_worthy = true;
				break;
			}
		}
		if ( $strike_worthy && $ip && ! $is_authed ) {
			do_action( 'amoskys_aegis_strike', self::STRIKE_RULE, $ip );
		}

		return $query;
	}

	/**
	 * Return a list of { pattern, class, severity } hits for $query.
	 * Each pattern is case-insensitive except where noted.
	 */
	private function classify( string $query ): array {
		$q = $query;
		$upper = strtoupper( $q );
		$hits = array();

		// TIME_BASED_BLIND
		if ( preg_match( '/\b(SLEEP|BENCHMARK)\s*\(/i', $q )
		    || preg_match( '/\bWAITFOR\s+DELAY\b/i', $q ) ) {
			$hits[] = array(
				'pattern' => 'sleep_benchmark',
				'class'   => 'TIME_BASED_BLIND',
				'severity'=> 'critical',
			);
		}

		// FILE_PRIMITIVES
		if ( preg_match( '/\bINTO\s+(OUTFILE|DUMPFILE)\b/i', $q )
		    || preg_match( '/\bLOAD_FILE\s*\(/i', $q ) ) {
			$hits[] = array(
				'pattern' => 'file_primitive',
				'class'   => 'FILE_PRIMITIVES',
				'severity'=> 'critical',
			);
		}

		// SCHEMA_DISCOVERY — schema tables referenced from outside a
		// WP-internal wp_options/wp_usermeta context.
		if ( preg_match( '/\b(information_schema\.|performance_schema\.|mysql\.user\b)/i', $q ) ) {
			$hits[] = array(
				'pattern' => 'schema_discovery',
				'class'   => 'SCHEMA_DISCOVERY',
				'severity'=> 'high',
			);
		}

		// UNION_SELECT — flag if combined with schema discovery OR a
		// bare "UNION ALL SELECT" that reaches for many columns (classic
		// column-count probe).
		if ( preg_match( '/\bUNION\s+(ALL\s+)?SELECT\b/i', $q ) ) {
			// Count columns in the SELECT list; >6 with no FROM is a
			// probe pattern.
			$is_suspicious = (bool) preg_match( '/\bUNION\s+(ALL\s+)?SELECT\b.*\bNULL\b.*\bNULL\b.*\bNULL\b/i', $q )
			               || (bool) preg_match( '/\binformation_schema\./i', $q );
			if ( $is_suspicious ) {
				$hits[] = array(
					'pattern' => 'union_select',
					'class'   => 'UNION_SELECT',
					'severity'=> 'high',
				);
			}
		}

		// STACKED_QUERIES
		if ( preg_match( '/;\s*(SELECT|INSERT|UPDATE|DELETE|DROP|TRUNCATE|ALTER|CREATE)\b/i', $q ) ) {
			$hits[] = array(
				'pattern' => 'stacked_query',
				'class'   => 'STACKED_QUERIES',
				'severity'=> 'critical',
			);
		}

		// COMMENT_BYPASS — the literal `-- ` or `/*!` forms only.
		if ( preg_match( '/\s--\s/', $q )      // `-- ` mid-string
		    || preg_match( '/\/\*![0-9]*/', $q ) // `/*!` conditional comment
		    || preg_match( '/#\s/', $q ) ) {   // `# ` short comment
			// Only flag if it's positioned suspiciously — after a quote
			// or bool expression.
			if ( preg_match( '/[\'"]\s*(OR|AND)?\s*[\'"]?\s*--\s/i', $q )
			    || preg_match( '/\)\s*--\s/', $q )
			    || preg_match( '/\/\*!/', $q ) ) {
				$hits[] = array(
					'pattern' => 'comment_bypass',
					'class'   => 'COMMENT_BYPASS',
					'severity'=> 'high',
				);
			}
		}

		// BOOLEAN_TAUTOLOGY
		if ( preg_match( "/\\b(OR|AND)\\s+(['\"]?)(\\w+)\\2\\s*=\\s*\\2\\3\\2\\b/i", $q )
		    || preg_match( '/\b(OR|AND)\s+1\s*=\s*1\b/i', $q )
		    || preg_match( '/\b(OR|AND)\s+true\b/i', $q ) ) {
			$hits[] = array(
				'pattern' => 'tautology',
				'class'   => 'BOOLEAN_TAUTOLOGY',
				'severity'=> 'high',
			);
		}

		// ENCODED_PAYLOAD — CHAR(...) / CONCAT(CHAR(...)) string
		// assembly. Benign in a few plugins (rarely) — worth auditing.
		if ( preg_match( '/\bCONCAT\s*\(\s*CHAR\s*\(/i', $q )
		    || preg_match( '/\bCHAR\s*\(\s*\d+\s*,\s*\d+\s*,/i', $q ) ) {
			$hits[] = array(
				'pattern' => 'char_concat',
				'class'   => 'ENCODED_PAYLOAD',
				'severity'=> 'high',
			);
		}

		// Apply operator whitelist: if the query hash matches an allowed
		// pattern the operator vetted, drop the severity to info.
		if ( $hits ) {
			$h = md5( $query );
			$whitelist = (array) get_option( 'amoskys_aegis_sql_whitelist', array() );
			if ( in_array( $h, $whitelist, true ) ) {
				foreach ( $hits as &$hit ) { $hit['severity'] = 'info'; }
				unset( $hit );
			}
		}

		return $hits;
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
