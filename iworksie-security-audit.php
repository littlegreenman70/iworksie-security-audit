<?php
/**
 * Plugin Name:       iWorks.ie Security Audit
 * Plugin URI:        https://www.iworks.ie
 * Description:       A read-only security audit: finds exposed backups and config files, risky settings and abandoned plugins, then explains each fix in plain English. Not a firewall, so no background load.
 * Version:           1.0.0
 * Requires at least: 6.5
 * Requires PHP:      7.4
 * Author:            iWorks.ie
 * Author URI:        https://www.iworks.ie
 * License:           GPL-2.0-or-later
 * License URI:       https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain:       iworksie-security-audit
 * Domain Path:       /languages
 *
 * @package IWorksIE\SecurityAudit
 */

defined( 'ABSPATH' ) || exit;

define( 'IWIESA_VERSION', '1.0.0' );
define( 'IWIESA_FILE', __FILE__ );
define( 'IWIESA_PATH', plugin_dir_path( __FILE__ ) );
define( 'IWIESA_URL', plugin_dir_url( __FILE__ ) );
define( 'IWIESA_MIN_PHP', '7.4' );
define( 'IWIESA_MIN_WP', '6.5' );

/**
 * Admin notice when requirements are not met.
 *
 * @param string $message Notice text.
 * @return void
 */
function iwiesa_requirements_notice( $message ) {
	add_action(
		'admin_notices',
		static function () use ( $message ) {
			echo '<div class="notice notice-error"><p>' . esc_html( $message ) . '</p></div>';
		}
	);
}

if ( version_compare( PHP_VERSION, IWIESA_MIN_PHP, '<' ) ) {
	iwiesa_requirements_notice(
		sprintf(
			/* translators: 1: required PHP version, 2: current PHP version */
			__( 'iWorks.ie Security Audit requires PHP %1$s or higher. This site is running PHP %2$s.', 'iworksie-security-audit' ),
			IWIESA_MIN_PHP,
			PHP_VERSION
		)
	);
	return;
}

global $wp_version;
if ( isset( $wp_version ) && version_compare( $wp_version, IWIESA_MIN_WP, '<' ) ) {
	iwiesa_requirements_notice(
		sprintf(
			/* translators: 1: required WordPress version, 2: current WordPress version */
			__( 'iWorks.ie Security Audit requires WordPress %1$s or higher. This site is running WordPress %2$s.', 'iworksie-security-audit' ),
			IWIESA_MIN_WP,
			$wp_version
		)
	);
	return;
}

$iwiesa_prefixed = IWIESA_PATH . 'vendor-prefixed/autoload.php';
if ( ! is_readable( $iwiesa_prefixed ) ) {
	iwiesa_requirements_notice(
		__( 'iWorks.ie Security Audit is missing its vendor-prefixed library. Run composer install, or install the release zip from wordpress.org.', 'iworksie-security-audit' )
	);
	return;
}
require_once $iwiesa_prefixed;

$iwiesa_autoload = IWIESA_PATH . 'vendor/autoload.php';
if ( is_readable( $iwiesa_autoload ) ) {
	require_once $iwiesa_autoload;
} else {
	spl_autoload_register(
		static function ( $class_name ) {
			$prefix = 'IWorksIE\\SecurityAudit\\';
			if ( 0 !== strpos( $class_name, $prefix ) ) {
				return;
			}
			$relative = substr( $class_name, strlen( $prefix ) );
			$file     = IWIESA_PATH . 'src/' . str_replace( '\\', '/', $relative ) . '.php';
			if ( is_readable( $file ) ) {
				require_once $file;
			}
		}
	);
}

add_action(
	'plugins_loaded',
	static function () {
		if ( ! class_exists( '\IWorksIE\SecurityAudit\Vendor\IWorksIE\Core\Core' ) ) {
			iwiesa_requirements_notice(
				__( 'iWorks.ie Security Audit could not load its shared tools library.', 'iworksie-security-audit' )
			);
			return;
		}
		// Nothing runs on the front end: boot only for wp-admin, AJAX, cron (weekly email) and WP-CLI.
		if ( ! is_admin() && ! wp_doing_cron() && ! ( defined( 'WP_CLI' ) && WP_CLI ) ) {
			return;
		}
		// Boot after init so __() / translate() are not called too early (WP 6.7+).
		add_action(
			'init',
			static function () {
				\IWorksIE\SecurityAudit\Plugin::instance()->boot();
			},
			5
		);
	},
	5
);

register_deactivation_hook(
	__FILE__,
	static function () {
		wp_clear_scheduled_hook( 'iwiesa_weekly_audit' );
	}
);
