<?php
/**
 * World-writable files and folders.
 *
 * @package IWorksIE\SecurityAudit
 */

namespace IWorksIE\SecurityAudit\Checks\Server;

use IWorksIE\SecurityAudit\Checks\BaseCheck;
use IWorksIE\SecurityAudit\Support\FileExposure;
use IWorksIE\SecurityAudit\Vendor\IWorksIE\Core\Checks\Result;

/**
 * Key paths that any user on the server could change.
 */
final class FilePermissionsCheck extends BaseCheck {

	/** @return string */
	public function id() {
		return 'file_permissions';
	}

	/** @return string */
	public function label() {
		return __( 'File permissions', 'iworksie-security-audit' );
	}

	/** @return string */
	public function group() {
		return 'server';
	}

	/** @return Result */
	public function run() {
		$why = __( 'A file that is "world-writable" (permission 777 or 666) can be changed by any account or script on the server. On shared hosting that can include other customers\' hacked sites.', 'iworksie-security-audit' );

		if ( '\\' === DIRECTORY_SEPARATOR ) {
			return $this->result( 'info', __( 'This server runs Windows, where these permission checks do not apply.', 'iworksie-security-audit' ), $why, $this->no_action() );
		}

		$matches = array();
		foreach ( $this->paths() as $path ) {
			if ( ! file_exists( $path ) ) {
				continue;
			}
			$perms = @fileperms( $path ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
			if ( false === $perms ) {
				continue;
			}
			if ( self::is_world_writable( $perms ) ) {
				$matches[] = array(
					'relative' => FileExposure::relative( $path ) . ( is_dir( $path ) ? '/' : '' ),
					'kind'     => self::octal( $perms ),
				);
			}
		}

		$config = $this->config_path();
		if ( '' !== $config ) {
			$perms = @fileperms( $config ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
			if ( false !== $perms && self::is_world_writable( $perms ) ) {
				$matches[] = array(
					'relative' => FileExposure::relative( $config ),
					'kind'     => self::octal( $perms ),
				);
			}
		}

		if ( ! empty( $matches ) ) {
			return $this->result(
				'critical',
				__( 'Some important files or folders can be changed by anyone on the server.', 'iworksie-security-audit' ),
				$why,
				__( 'Ask your host (or use your file manager) to set folders to 755 and files to 644; wp-config.php can be 640 or 600. Never use 777.', 'iworksie-security-audit' ),
				array( 'matches' => $matches )
			);
		}
		return $this->result( 'good', __( 'wp-config.php, .htaccess and the main WordPress folders are not world-writable.', 'iworksie-security-audit' ), $why, $this->no_action() );
	}

	/**
	 * Whether a permission mask lets "others" write. Pure function.
	 *
	 * @param int $perms fileperms() value.
	 * @return bool
	 */
	public static function is_world_writable( $perms ) {
		return 0 !== ( (int) $perms & 0002 );
	}

	/**
	 * e.g. 0777.
	 *
	 * @param int $perms fileperms() value.
	 * @return string
	 */
	public static function octal( $perms ) {
		return substr( sprintf( '%o', (int) $perms ), -4 );
	}

	/**
	 * Paths checked (not recursive).
	 *
	 * @return array<int,string>
	 */
	private function paths() {
		$root    = untrailingslashit( wp_normalize_path( ABSPATH ) );
		$content = untrailingslashit( wp_normalize_path( WP_CONTENT_DIR ) );
		$paths   = array(
			$root,
			$root . '/.htaccess',
			$root . '/index.php',
			$root . '/wp-admin',
			$root . '/wp-includes',
			$content,
			$content . '/plugins',
			$content . '/themes',
			$content . '/mu-plugins',
		);
		return array_values( array_unique( $paths ) );
	}

	/**
	 * wp-config.php may live one folder above ABSPATH.
	 *
	 * @return string
	 */
	private function config_path() {
		$root = untrailingslashit( wp_normalize_path( ABSPATH ) );
		if ( file_exists( $root . '/wp-config.php' ) ) {
			return $root . '/wp-config.php';
		}
		$parent = dirname( $root ) . '/wp-config.php';
		if ( @file_exists( $parent ) && ! @file_exists( dirname( $root ) . '/wp-settings.php' ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- open_basedir may forbid the parent folder.
			return $parent;
		}
		return '';
	}
}
