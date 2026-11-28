<?php
/**
 * PHPUnit bootstrap.
 *
 * @package IWorksIE\SecurityAudit
 */

$iwiesa_root = dirname( __DIR__ );

require_once $iwiesa_root . '/vendor/autoload.php';

$iwiesa_prefixed = $iwiesa_root . '/vendor-prefixed/autoload.php';
if ( is_readable( $iwiesa_prefixed ) ) {
	require_once $iwiesa_prefixed;
}

$iwiesa_suite = getenv( 'IWIESA_TESTSUITE' );
if ( ! $iwiesa_suite ) {
	$iwiesa_suite = 'unit';
}

if ( 'integration' === $iwiesa_suite ) {
	$iwiesa_wp_tests = getenv( 'WP_TESTS_DIR' );
	if ( ! $iwiesa_wp_tests ) {
		$iwiesa_wp_tests = $iwiesa_root . '/tests/wordpress/wordpress-tests-lib';
	}
	if ( ! is_readable( $iwiesa_wp_tests . '/includes/functions.php' ) ) {
		fwrite( STDERR, "WP test suite not found at {$iwiesa_wp_tests}. Run bin/install-wp-tests.sh first.\n" );
		exit( 1 );
	}
	require_once $iwiesa_wp_tests . '/includes/functions.php';

	tests_add_filter(
		'muplugins_loaded',
		static function () use ( $iwiesa_root ) {
			$plugin = $iwiesa_root . '/iworksie-security-audit.php';
			if ( is_readable( $plugin ) ) {
				require $plugin;
				// The plugin only boots in wp-admin, cron and WP-CLI; boot it for tests too.
				add_action(
					'init',
					static function () {
						\IWorksIE\SecurityAudit\Plugin::instance()->boot();
					},
					5
				);
			}
			$ex1 = dirname( $iwiesa_root ) . '/iworks-tools-core/examples/iworksie-example-one/iworksie-example-one.php';
			$ex2 = dirname( $iwiesa_root ) . '/iworks-tools-core/examples/iworksie-example-two/iworksie-example-two.php';
			if ( is_readable( $ex1 ) ) {
				require $ex1;
			}
			if ( is_readable( $ex2 ) ) {
				require $ex2;
			}
		}
	);

	require_once $iwiesa_wp_tests . '/includes/bootstrap.php';
}
