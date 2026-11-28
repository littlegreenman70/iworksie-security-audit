<?php
/**
 * Find sensitive files on disk and prove whether the public can download them.
 *
 * @package IWorksIE\SecurityAudit
 */

namespace IWorksIE\SecurityAudit\Support;

/**
 * Two steps, so the audit never guesses:
 * 1. List files in a few public folders (no recursion) whose names mark them as
 *    secrets, backups, logs or version-control folders.
 * 2. Request each one anonymously and only call it "exposed" when the response
 *    is a real download whose content matches the file type (not a 404 page).
 */
final class FileExposure {

	const CATEGORY_SECRETS = 'secrets';
	const CATEGORY_BACKUPS = 'backups';
	const CATEGORY_VCS     = 'vcs';
	const CATEGORY_LOGS    = 'logs';

	/**
	 * Most files probed per check.
	 */
	const MAX_PROBES = 15;

	/**
	 * Seconds of probing per check before the rest are listed as "not confirmed".
	 */
	const TIME_BUDGET = 15;

	/**
	 * Folders inside wp-content that backup plugins use and normally protect.
	 * Files here are only reported when actually downloadable.
	 *
	 * @var array<int,string>
	 */
	const BACKUP_PLUGIN_DIRS = array(
		'updraft',
		'ai1wm-backups',
		'backups-dup-lite',
		'backups-dup-pro',
		'backup-db',
		'backups',
		'backup',
		'wpvividbackups',
		'backwpup',
	);

	/**
	 * Run the audit for one category.
	 *
	 * @param string $category One of the CATEGORY_* constants.
	 * @return array{exposed:array<int,array<string,mixed>>,blocked:array<int,array<string,mixed>>,unconfirmed:array<int,array<string,mixed>>,probe_error:string}
	 */
	public static function audit( $category ) {
		$out = array(
			'exposed'     => array(),
			'blocked'     => array(),
			'unconfirmed' => array(),
			'probe_error' => '',
		);

		$started = microtime( true );
		$probed  = 0;
		foreach ( self::candidates( $category ) as $candidate ) {
			$out_of_budget = $probed >= self::MAX_PROBES || ( microtime( true ) - $started ) > self::TIME_BUDGET;
			if ( $out_of_budget ) {
				$out['unconfirmed'][] = $candidate;
				continue;
			}
			++$probed;
			$response = Probe::fetch(
				$candidate['probe_url'],
				'GET',
				array( 'headers' => array( 'Range' => 'bytes=0-' . ( Probe::BODY_LIMIT - 1 ) ) )
			);
			if ( ! $response['reachable'] ) {
				$out['probe_error']   = $response['error'];
				$out['unconfirmed'][] = $candidate;
				continue;
			}
			if ( Probe::is_ok( $response ) && self::matches_signature( (string) $candidate['signature'], $response['body'] ) ) {
				$out['exposed'][] = $candidate;
				continue;
			}
			if ( empty( $candidate['quiet_if_blocked'] ) ) {
				$out['blocked'][] = $candidate;
			}
		}
		return $out;
	}

	/**
	 * Files and folders on disk that belong to a category.
	 *
	 * @param string $category Category.
	 * @return array<int,array<string,mixed>>
	 */
	public static function candidates( $category ) {
		$found = array();
		$seen  = array();
		foreach ( self::scan_dirs() as $dir ) {
			$entries = @scandir( $dir['path'] ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- unreadable folders are skipped.
			if ( ! is_array( $entries ) ) {
				continue;
			}
			foreach ( $entries as $name ) {
				if ( '.' === $name || '..' === $name ) {
					continue;
				}
				$full   = rtrim( $dir['path'], '/' ) . '/' . $name;
				$is_dir = is_dir( $full );
				$rule   = self::classify_name( $name, $is_dir );
				if ( null === $rule || $rule['category'] !== $category ) {
					continue;
				}
				$real = realpath( $full );
				$key  = false !== $real ? $real : $full;
				if ( isset( $seen[ $key ] ) ) {
					continue;
				}
				$seen[ $key ] = true;

				$size    = $is_dir ? 0 : (int) @filesize( $full ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
				$url     = rtrim( $dir['url'], '/' ) . '/' . rawurlencode( $name );
				$found[] = array(
					'path'             => wp_normalize_path( $full ),
					'relative'         => self::relative( $full ) . ( $is_dir ? '/' : '' ),
					'url'              => $url,
					'probe_url'        => $url . $rule['probe_suffix'],
					'signature'        => $rule['signature'],
					'is_dir'           => $is_dir,
					'bytes'            => $size,
					'quiet_if_blocked' => ! empty( $dir['quiet'] ),
				);
			}
		}

		// Biggest first so the most serious leaks are probed inside the budget.
		usort(
			$found,
			static function ( $a, $b ) {
				return (int) $b['bytes'] <=> (int) $a['bytes'];
			}
		);
		return $found;
	}

	/**
	 * Decide what a file or folder name means. Pure function (unit tested).
	 *
	 * @param string $name   Base name.
	 * @param bool   $is_dir Whether it is a directory.
	 * @return array{category:string,signature:string,probe_suffix:string}|null
	 */
	public static function classify_name( $name, $is_dir ) {
		$name  = (string) $name;
		$lower = strtolower( $name );

		if ( $is_dir ) {
			$vcs = array(
				'.git' => array( 'git_head', '/HEAD' ),
				'.svn' => array( 'svn_db', '/wc.db' ),
				'.hg'  => array( 'any', '/requires' ),
			);
			if ( isset( $vcs[ $lower ] ) ) {
				return self::rule( self::CATEGORY_VCS, $vcs[ $lower ][0], $vcs[ $lower ][1] );
			}
			return null;
		}

		if ( '.env' === $lower || 0 === strpos( $lower, '.env.' ) ) {
			// .env.example / .env.sample are templates, not secrets.
			if ( preg_match( '/\.(example|sample|dist|template)$/', $lower ) ) {
				return null;
			}
			return self::rule( self::CATEGORY_SECRETS, 'env' );
		}
		if ( '.htpasswd' === $lower ) {
			return self::rule( self::CATEGORY_SECRETS, 'htpasswd' );
		}
		// Copies of wp-config that the server would send as text (anything not ending in .php).
		if ( preg_match( '/^\.?wp-config/', $lower ) && ! preg_match( '/\.php$/', $lower ) ) {
			return self::rule( self::CATEGORY_SECRETS, 'wpconfig' );
		}
		if ( in_array( $lower, array( 'phpinfo.php', 'info.php', 'php-info.php', 'php_info.php', 'pi.php', 'phpinfo.php5', 'test-phpinfo.php' ), true ) ) {
			return self::rule( self::CATEGORY_SECRETS, 'phpinfo' );
		}

		if ( in_array( $lower, array( 'error_log', 'php_errorlog' ), true ) || preg_match( '/\.log$/', $lower ) ) {
			return self::rule( self::CATEGORY_LOGS, 'log' );
		}

		$archives = array(
			'/\.sql$/'                            => 'sql',
			'/\.dump$/'                           => 'sql',
			'/\.(gz|tgz)$/'                       => 'gzip',
			'/\.zip$/'                            => 'zip',
			'/\.tar$/'                            => 'tar',
			'/\.bz2$/'                            => 'bzip2',
			'/\.7z$/'                             => '7z',
			'/\.rar$/'                            => 'rar',
			'/\.wpress$/'                         => 'any',
			'/\.(bak|backup|old|orig|save|swp)$/' => 'any',
			'/~$/'                                => 'any',
		);
		foreach ( $archives as $pattern => $signature ) {
			if ( preg_match( $pattern, $lower ) ) {
				return self::rule( self::CATEGORY_BACKUPS, $signature );
			}
		}
		return null;
	}

	/**
	 * Whether a downloaded body really is the kind of file we expected. Pure function.
	 *
	 * @param string $signature Signature key.
	 * @param string $body      First bytes of the response.
	 * @return bool
	 */
	public static function matches_signature( $signature, $body ) {
		$body = (string) $body;
		if ( '' === trim( $body ) ) {
			return false;
		}
		$html = Probe::looks_like_html( $body );
		switch ( $signature ) {
			case 'env':
				return ! $html && 1 === preg_match( '/^\s*(export\s+)?[A-Za-z_][A-Za-z0-9_]*\s*=/m', $body );
			case 'htpasswd':
				return ! $html && 1 === preg_match( '/^[^:\s<>]+:\S{4,}/m', $body );
			case 'wpconfig':
				return false !== strpos( $body, 'DB_NAME' ) || false !== strpos( $body, 'DB_PASSWORD' ) || false !== strpos( $body, '$table_prefix' );
			case 'phpinfo':
				return false !== stripos( $body, 'phpinfo()' ) || ( false !== strpos( $body, 'PHP Version' ) && false !== strpos( $body, 'System' ) );
			case 'git_head':
				return 1 === preg_match( '/^(ref:\s*refs\/|[0-9a-f]{40})/', trim( $body ) );
			case 'svn_db':
				return 0 === strpos( $body, 'SQLite format 3' );
			case 'sql':
				return ! $html && 1 === preg_match( '/(CREATE TABLE|INSERT INTO|DROP TABLE|-- MySQL dump|-- MariaDB dump|-- phpMyAdmin SQL Dump)/i', $body );
			case 'gzip':
				return 0 === strpos( $body, "\x1f\x8b" );
			case 'zip':
				return 0 === strpos( $body, "PK\x03\x04" ) || 0 === strpos( $body, "PK\x05\x06" );
			case 'tar':
				return 'ustar' === substr( $body, 257, 5 );
			case 'bzip2':
				return 0 === strpos( $body, 'BZh' );
			case '7z':
				return 0 === strpos( $body, "7z\xBC\xAF\x27\x1C" );
			case 'rar':
				return 0 === strpos( $body, 'Rar!' );
			case 'log':
			case 'any':
			default:
				return ! $html;
		}
	}

	/**
	 * Folders scanned (one level only) with the public URL each maps to.
	 *
	 * @return array<int,array{path:string,url:string,quiet:bool}>
	 */
	public static function scan_dirs() {
		$dirs = array();

		$home_path = self::home_path();
		if ( '' !== $home_path ) {
			$dirs[] = array(
				'path'  => $home_path,
				'url'   => home_url( '/' ),
				'quiet' => false,
			);
		}
		$dirs[]  = array(
			'path'  => wp_normalize_path( ABSPATH ),
			'url'   => site_url( '/' ),
			'quiet' => false,
		);
		$dirs[]  = array(
			'path'  => wp_normalize_path( WP_CONTENT_DIR ),
			'url'   => content_url( '/' ),
			'quiet' => false,
		);
		$uploads = wp_get_upload_dir();
		if ( empty( $uploads['error'] ) && ! empty( $uploads['basedir'] ) ) {
			$dirs[] = array(
				'path'  => wp_normalize_path( (string) $uploads['basedir'] ),
				'url'   => (string) $uploads['baseurl'],
				'quiet' => false,
			);
		}
		foreach ( self::BACKUP_PLUGIN_DIRS as $sub ) {
			$path = wp_normalize_path( WP_CONTENT_DIR ) . '/' . $sub;
			if ( is_dir( $path ) ) {
				$dirs[] = array(
					'path'  => $path,
					'url'   => content_url( '/' . $sub ),
					'quiet' => true,
				);
			}
		}

		// Drop duplicates (e.g. home path === ABSPATH).
		$unique = array();
		foreach ( $dirs as $dir ) {
			$real = realpath( $dir['path'] );
			$key  = false !== $real ? $real : $dir['path'];
			if ( ! isset( $unique[ $key ] ) ) {
				$unique[ $key ] = $dir;
			}
		}
		return array_values( $unique );
	}

	/**
	 * Path shown to people: relative to the site root.
	 *
	 * @param string $full Absolute path.
	 * @return string
	 */
	public static function relative( $full ) {
		$full = wp_normalize_path( (string) $full );
		$base = self::home_path();
		if ( '' === $base ) {
			$base = wp_normalize_path( ABSPATH );
		}
		$base = rtrim( $base, '/' ) . '/';
		if ( 0 === strpos( $full, $base ) ) {
			return substr( $full, strlen( $base ) );
		}
		return $full;
	}

	/**
	 * Absolute path of the folder home_url() serves (differs from ABSPATH when
	 * WordPress lives in a subfolder).
	 *
	 * @return string
	 */
	private static function home_path() {
		if ( ! function_exists( 'get_home_path' ) ) {
			require_once ABSPATH . 'wp-admin/includes/file.php';
		}
		$path = (string) get_home_path();
		// get_home_path() relies on SCRIPT_FILENAME, which can be odd under WP-CLI or cron.
		if ( '' === $path || ! is_dir( $path ) ) {
			return '';
		}
		return wp_normalize_path( $path );
	}

	/**
	 * @param string $category     Category.
	 * @param string $signature    Signature key.
	 * @param string $probe_suffix Appended to the URL (for folders).
	 * @return array{category:string,signature:string,probe_suffix:string}
	 */
	private static function rule( $category, $signature, $probe_suffix = '' ) {
		return array(
			'category'     => $category,
			'signature'    => $signature,
			'probe_suffix' => $probe_suffix,
		);
	}
}
