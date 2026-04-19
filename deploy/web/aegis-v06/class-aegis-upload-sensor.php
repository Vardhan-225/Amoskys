<?php
/**
 * AMOSKYS Aegis — Upload Runtime Classifier (v0.6)
 *
 * Defensive pair to argos/ast/file_upload.py.
 *
 * Hook surface
 * ─────────────────────────────────────────────────────────────────
 * WordPress fires `wp_handle_upload_prefilter` before it starts
 * processing any uploaded file (via wp_handle_upload or via the
 * Media admin page). The filter receives the $_FILES-shaped array
 * as its only argument. We tap it and look at three things:
 *
 *   1. File extension  — the final, dot-separated token of the name,
 *      lowercased. If it matches our executable-extension set,
 *      CRITICAL regardless of claimed MIME.
 *
 *   2. Double-extension — any token between dots that is an exec
 *      extension, even if the final token isn't (e.g. shell.php.jpg,
 *      shell.phtml.png). These are the classic Apache mod_rewrite
 *      and IIS extension-parsing bypasses.
 *
 *   3. Content sniff — read first 4 KB of the temp file and look for
 *      PHP open tags (<?php, <?=, <%, <script language="php"),
 *      shebang lines (#!), Perl/Python syntax markers, .htaccess
 *      directives. Any hit = CRITICAL.
 *
 *   4. Declared MIME vs content MIME — finfo the temp file; if the
 *      detected type doesn't match the declared one or an expected
 *      family (image/* when extension is .jpg), raise HIGH.
 *
 * Response ladder
 * ─────────────────────────────────────────────────────────────────
 *   - All four checks emit `aegis.media.dangerous_upload` at the
 *     classified severity.
 *   - CRITICAL hits fire do_action('amoskys_aegis_strike',
 *     'file_upload_attempt', $ip) — threshold = 1 → instant block.
 *   - High/medium hits emit but don't auto-block (auth'd admins
 *     sometimes upload borderline files; operator reviews).
 *
 * Non-blocking — we NEVER alter or reject the upload from this
 * filter. WordPress and other security plugins have stronger claim
 * on that; we observe and strike. If the upload would have succeeded
 * without us, it still does. Our response is the block on the NEXT
 * request from that IP.
 *
 * @package AmoskysAegis
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Amoskys_Aegis_Upload_Sensor {

	/** @var Amoskys_Aegis_Emitter */
	private $emitter;

	/**
	 * Strike rule name, paired with the v0.4 block engine.
	 * Threshold is 1 — ONE dangerous upload attempt should block.
	 */
	const STRIKE_RULE = 'file_upload_attempt';

	/** Executable/scriptable extensions we refuse to treat as media. */
	const EXEC_EXTS = array(
		'php', 'php3', 'php4', 'php5', 'php7', 'php8',
		'phtml', 'phar', 'pht', 'phps',
		'inc',
		'cgi', 'pl', 'py', 'sh', 'rb', 'lua',
		'htaccess', 'user', 'ini', 'htpasswd',
	);

	/** Bytes we read from the tmp file for content sniffing. */
	const CONTENT_SNIFF_BYTES = 4096;

	public function __construct( Amoskys_Aegis_Emitter $emitter ) {
		$this->emitter = $emitter;
	}

	public function register(): void {
		// Priority 9 — before WordPress core's own validation at 10 so we
		// see the unmodified $_FILES. We never mutate $file.
		add_filter( 'wp_handle_upload_prefilter', array( $this, 'inspect_upload' ), 9 );
	}

	/**
	 * @param array $file { name, type, tmp_name, error, size }
	 * @return array unchanged
	 */
	public function inspect_upload( $file ) {
		if ( ! is_array( $file ) || empty( $file['name'] ) ) {
			return $file;
		}
		// Skip failed uploads — no content to analyze.
		if ( ! empty( $file['error'] ) && (int) $file['error'] !== 0 ) {
			return $file;
		}

		$name      = (string) $file['name'];
		$tmp       = isset( $file['tmp_name'] ) ? (string) $file['tmp_name'] : '';
		$claimed   = isset( $file['type'] ) ? strtolower( (string) $file['type'] ) : '';
		$size      = isset( $file['size'] ) ? (int) $file['size'] : 0;

		$findings = array();

		// 1 & 2: extension checks.
		$ext_finding = $this->classify_extensions( $name );
		if ( $ext_finding ) {
			$findings[] = $ext_finding;
		}

		// 3: content sniff.
		if ( $tmp && file_exists( $tmp ) && is_readable( $tmp ) ) {
			$content_finding = $this->classify_content( $tmp );
			if ( $content_finding ) {
				$findings[] = $content_finding;
			}
		}

		// 4: MIME vs extension divergence.
		if ( $tmp && file_exists( $tmp ) && is_readable( $tmp ) ) {
			$mime_finding = $this->classify_mime_divergence( $tmp, $name, $claimed );
			if ( $mime_finding ) {
				$findings[] = $mime_finding;
			}
		}

		if ( empty( $findings ) ) {
			return $file;
		}

		// Pick highest severity present.
		$sev_rank = array( 'info' => 0, 'low' => 1, 'medium' => 2, 'high' => 3, 'critical' => 4 );
		$top_sev = 'medium';
		foreach ( $findings as $f ) {
			if ( $sev_rank[ $f['severity'] ] > $sev_rank[ $top_sev ] ) {
				$top_sev = $f['severity'];
			}
		}

		$ip     = $this->get_ip();
		$user_id = get_current_user_id();
		$user_role = $this->current_role();

		$this->emitter->emit(
			'aegis.media.dangerous_upload',
			array(
				'ip'            => $ip,
				'user_id'       => $user_id,
				'user_role'     => $user_role,
				'name'          => $name,
				'claimed_mime'  => $claimed,
				'size'          => $size,
				'patterns'      => array_values( array_unique( array_column( $findings, 'pattern' ) ) ),
				'classes'       => array_values( array_unique( array_column( $findings, 'class' ) ) ),
				'details'       => $findings,
			),
			$top_sev
		);

		// Strike only on CRITICAL — any kind of executable-content upload,
		// regardless of whether the user is authed. We strike admins too,
		// because if an admin is pushing PHP into uploads, either their
		// session is hijacked or they're doing something they shouldn't be.
		if ( $top_sev === 'critical' && $ip ) {
			do_action( 'amoskys_aegis_strike', self::STRIKE_RULE, $ip );
		}

		return $file;
	}

	/**
	 * Return a finding dict on dangerous extension OR double-extension
	 * bypass, else null.
	 */
	private function classify_extensions( string $name ) {
		$lower = strtolower( $name );
		$parts = explode( '.', $lower );
		if ( count( $parts ) < 2 ) {
			return null;
		}
		// 1. Final extension.
		$final = end( $parts );
		if ( in_array( $final, self::EXEC_EXTS, true ) ) {
			return array(
				'pattern' => 'exec_extension',
				'class'   => 'EXECUTABLE_EXTENSION',
				'severity'=> 'critical',
				'ext'     => $final,
			);
		}
		// 2. Double-extension bypass: any non-final dot-token is exec.
		// Skip the first part (filename stem) and the last (final ext).
		$middle = array_slice( $parts, 1, -1 );
		foreach ( $middle as $tok ) {
			if ( in_array( $tok, self::EXEC_EXTS, true ) ) {
				return array(
					'pattern' => 'double_extension',
					'class'   => 'DOUBLE_EXTENSION_BYPASS',
					'severity'=> 'critical',
					'ext'     => $tok,
				);
			}
		}
		return null;
	}

	/**
	 * Sniff the first N bytes of the tmp file for server-executable
	 * content. Returns a finding dict on hit, else null.
	 */
	private function classify_content( string $tmp ) {
		$fh = @fopen( $tmp, 'rb' );
		if ( ! $fh ) {
			return null;
		}
		$bytes = @fread( $fh, self::CONTENT_SNIFF_BYTES );
		@fclose( $fh );
		if ( ! is_string( $bytes ) || $bytes === '' ) {
			return null;
		}

		// PHP open tags. <? alone is short-tag, commonly enabled — so we
		// flag it too. <?xml is a false-positive; we exclude it.
		if ( preg_match( '/<\?php/i', $bytes )
		  || preg_match( '/<\?=/', $bytes )
		  || ( preg_match( '/<\?/', $bytes ) && ! preg_match( '/<\?xml\b/i', $bytes ) )
		  || preg_match( '/<script\s+language\s*=\s*["\']?php/i', $bytes ) ) {
			return array(
				'pattern' => 'php_open_tag',
				'class'   => 'EXECUTABLE_CONTENT',
				'severity'=> 'critical',
			);
		}
		// ASP short / classic.
		if ( preg_match( '/<%\s/', $bytes ) || preg_match( '/<%@/', $bytes ) ) {
			return array(
				'pattern' => 'asp_tag',
				'class'   => 'EXECUTABLE_CONTENT',
				'severity'=> 'critical',
			);
		}
		// Shebang — shell scripts.
		if ( substr( $bytes, 0, 2 ) === '#!' ) {
			return array(
				'pattern' => 'shebang',
				'class'   => 'EXECUTABLE_CONTENT',
				'severity'=> 'high',
			);
		}
		// .htaccess directives — rewriting rules / AddType attacks.
		if ( preg_match( '/^\s*(AddType|AddHandler|SetHandler|RewriteRule|Options\s+\+ExecCGI)\b/mi', $bytes ) ) {
			return array(
				'pattern' => 'htaccess_directive',
				'class'   => 'EXECUTABLE_CONTENT',
				'severity'=> 'critical',
			);
		}
		// Perl / Python obvious markers at start of file.
		if ( preg_match( '/^\s*(use\s+strict|package\s+\w+)\b/', $bytes )
		  || preg_match( '/^\s*(from\s+\w+\s+import\b|def\s+\w+\s*\(|import\s+os\b)/', $bytes ) ) {
			return array(
				'pattern' => 'scripting_language',
				'class'   => 'EXECUTABLE_CONTENT',
				'severity'=> 'high',
			);
		}
		return null;
	}

	/**
	 * If the claimed MIME or the extension disagrees with the detected
	 * content type, raise HIGH.
	 */
	private function classify_mime_divergence( string $tmp, string $name, string $claimed ) {
		if ( ! function_exists( 'finfo_open' ) ) {
			return null;
		}
		$f = @finfo_open( FILEINFO_MIME_TYPE );
		if ( ! $f ) {
			return null;
		}
		$detected = @finfo_file( $f, $tmp );
		@finfo_close( $f );
		if ( ! $detected ) {
			return null;
		}
		$detected = strtolower( (string) $detected );

		// If detected says text/x-php — regardless of extension — flag.
		if ( strpos( $detected, 'x-php' ) !== false
		  || strpos( $detected, 'php' ) !== false
		  || strpos( $detected, 'x-shellscript' ) !== false ) {
			return array(
				'pattern' => 'mime_is_executable',
				'class'   => 'EXECUTABLE_CONTENT',
				'severity'=> 'critical',
				'detected_mime' => $detected,
			);
		}

		// Extension family vs detected: image/* extensions must detect
		// image/*; video/* must detect video/*; etc.
		$ext = strtolower( pathinfo( $name, PATHINFO_EXTENSION ) );
		$expected_family = $this->extension_family( $ext );
		if ( $expected_family && strpos( $detected, $expected_family . '/' ) !== 0 ) {
			return array(
				'pattern' => 'mime_family_mismatch',
				'class'   => 'MIME_DIVERGENCE',
				'severity'=> 'high',
				'ext'     => $ext,
				'detected_mime' => $detected,
				'expected_family' => $expected_family,
			);
		}

		// Claimed vs detected: mild signal when both are known families.
		if ( $claimed && strpos( $claimed, '/' ) !== false && strpos( $detected, '/' ) !== false ) {
			list( $c_fam, ) = explode( '/', $claimed, 2 );
			list( $d_fam, ) = explode( '/', $detected, 2 );
			if ( $c_fam !== $d_fam && $c_fam !== 'application' && $d_fam !== 'application' ) {
				return array(
					'pattern' => 'claimed_vs_detected_mime',
					'class'   => 'MIME_DIVERGENCE',
					'severity'=> 'medium',
					'claimed' => $claimed,
					'detected' => $detected,
				);
			}
		}
		return null;
	}

	/** Map extension → expected top-level MIME family, or null if unknown. */
	private function extension_family( string $ext ): ?string {
		static $map = null;
		if ( $map === null ) {
			$map = array(
				'jpg' => 'image', 'jpeg' => 'image', 'png' => 'image',
				'gif' => 'image', 'webp' => 'image', 'bmp' => 'image',
				'svg' => 'image',
				'mp3' => 'audio', 'wav' => 'audio', 'ogg' => 'audio',
				'mp4' => 'video', 'mov' => 'video', 'webm' => 'video',
				'pdf' => 'application', // application/pdf
			);
		}
		return $map[ $ext ] ?? null;
	}

	private function current_role(): string {
		$u = wp_get_current_user();
		if ( $u && ! empty( $u->roles ) ) {
			return (string) $u->roles[0];
		}
		return 'anonymous';
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
