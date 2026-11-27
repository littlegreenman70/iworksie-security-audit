<?php
/**
 * Errors shown to visitors / debug log in a public place.
 *
 * @package IWorksIE\SecurityAudit
 */

namespace IWorksIE\SecurityAudit\Checks\Config;

use IWorksIE\SecurityAudit\Checks\BaseCheck;
use IWorksIE\SecurityAudit\Vendor\IWorksIE\Core\Checks\Result;

/**
 * WP_DEBUG / WP_DEBUG_DISPLAY / display_errors / WP_DEBUG_LOG.
 */
final class DebugDisplayCheck extends BaseCheck {

	/** @return string */
	public function id() {
		return 'debug_display';
	}

	/** @return string */
	public function label() {
		return __( 'Error messages shown to visitors', 'iworksie-security-audit' );
	}

	/** @return string */
	public function group() {
		return 'config';
	}

	/** @return Result */
	public function run() {
		$debug       = defined( 'WP_DEBUG' ) && WP_DEBUG;
		$wp_display  = $debug && ( ! defined( 'WP_DEBUG_DISPLAY' ) || WP_DEBUG_DISPLAY );
		$ini_display = self::display_errors_on( self::server_display_errors() );
		$log         = $debug && defined( 'WP_DEBUG_LOG' ) ? constant( 'WP_DEBUG_LOG' ) : false;
		$public_log  = true === $log || ( is_string( $log ) && '' !== $log && $this->inside_web_root( $log ) );

		$why  = __( 'PHP errors show file paths, plugin names and sometimes database details to anyone who triggers them. Attackers use this to find weak spots.', 'iworksie-security-audit' );
		$fix  = __( 'In wp-config.php set define( \'WP_DEBUG\', false ); or keep debugging on but hidden with define( \'WP_DEBUG_DISPLAY\', false ); and @ini_set( \'display_errors\', 0 );', 'iworksie-security-audit' );
		$data = array(
			'wp_debug'         => $debug,
			'wp_debug_display' => $wp_display,
			'display_errors'   => $ini_display,
			'public_log'       => $public_log,
		);

		if ( $wp_display || ( $ini_display && ! ( $debug && defined( 'WP_DEBUG_DISPLAY' ) && ! WP_DEBUG_DISPLAY ) ) ) {
			$status = $this->is_dev_environment() ? 'info' : ( $wp_display ? 'critical' : 'recommended' );
			$text   = $wp_display
				? __( 'WP_DEBUG is on and errors are printed on the page for every visitor to see.', 'iworksie-security-audit' )
				: __( 'PHP is set to show errors on the page (display_errors is on). Warnings will be visible to visitors.', 'iworksie-security-audit' );
			if ( 'info' === $status ) {
				$text .= ' ' . __( 'This site is marked as a local or development copy, so this is fine here. Make sure it is off on the live site.', 'iworksie-security-audit' );
			}
			return $this->result( $status, $text, $why, $fix, $data );
		}

		if ( $public_log ) {
			return $this->result(
				$this->is_dev_environment() ? 'info' : 'recommended',
				__( 'Errors are hidden from visitors, but the debug log is written inside the website folder (wp-content/debug.log by default), where it can be downloaded.', 'iworksie-security-audit' ),
				$why,
				__( 'Point the log outside the website folder, for example define( \'WP_DEBUG_LOG\', \'/home/you/logs/wp-debug.log\' ); or turn it off when you are not debugging.', 'iworksie-security-audit' ),
				$data
			);
		}

		return $this->result( 'good', __( 'Errors are not shown to visitors.', 'iworksie-security-audit' ), $why, $this->no_action(), $data );
	}

	/**
	 * The server's display_errors setting. WordPress switches it off for AJAX
	 * requests (where this check runs), so prefer the configured value.
	 *
	 * @return string
	 */
	private static function server_display_errors() {
		if ( function_exists( 'ini_get_all' ) ) {
			$all = @ini_get_all( null, true ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- may be disabled by the host.
			if ( is_array( $all ) && isset( $all['display_errors']['global_value'] ) ) {
				return (string) $all['display_errors']['global_value'];
			}
		}
		return (string) ini_get( 'display_errors' );
	}

	/**
	 * Whether a display_errors value means "on". Pure function.
	 *
	 * @param string $value Ini value.
	 * @return bool
	 */
	public static function display_errors_on( $value ) {
		return in_array( strtolower( trim( (string) $value ) ), array( '1', 'on', 'true', 'yes', 'stdout', 'stderr' ), true );
	}

	/**
	 * Whether a path sits inside the public website folder.
	 *
	 * @param string $path Log path.
	 * @return bool
	 */
	private function inside_web_root( $path ) {
		$path = wp_normalize_path( (string) $path );
		$root = rtrim( wp_normalize_path( ABSPATH ), '/' ) . '/';
		return 0 === strpos( $path, $root );
	}
}
