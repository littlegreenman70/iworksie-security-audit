<?php
/**
 * PHPStan bootstrap stubs.
 *
 * @package IWorksIE\SecurityAudit
 */

if ( ! defined( 'ABSPATH' ) ) {
	define( 'ABSPATH', '/tmp/wordpress/' );
}
if ( ! defined( 'IWIESA_VERSION' ) ) {
	define( 'IWIESA_VERSION', '1.0.0' );
}
if ( ! defined( 'IWIESA_FILE' ) ) {
	define( 'IWIESA_FILE', '/tmp/iworksie-security-audit/iworksie-security-audit.php' );
}
if ( ! defined( 'IWIESA_PATH' ) ) {
	define( 'IWIESA_PATH', '/tmp/iworksie-security-audit/' );
}
if ( ! defined( 'IWIESA_URL' ) ) {
	define( 'IWIESA_URL', 'https://example.com/wp-content/plugins/iworksie-security-audit/' );
}
if ( ! defined( 'IWIESA_MIN_PHP' ) ) {
	define( 'IWIESA_MIN_PHP', '7.4' );
}
if ( ! defined( 'IWIESA_MIN_WP' ) ) {
	define( 'IWIESA_MIN_WP', '6.5' );
}

if ( ! class_exists( '\IWorksIE\SecurityAudit\Vendor\IWorksIE\Core\Core' ) && is_readable( dirname( __DIR__ ) . '/vendor-prefixed/autoload.php' ) ) {
	require_once dirname( __DIR__ ) . '/vendor-prefixed/autoload.php';
}
