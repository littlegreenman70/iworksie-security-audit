<?php
/**
 * Weekly schedule, email composition, menu and uninstall.
 *
 * @package IWorksIE\SecurityAudit
 */

namespace IWorksIE\SecurityAudit\Tests\Integration;

use IWorksIE\SecurityAudit\Support\WeeklyEmail;
use IWorksIE\SecurityAudit\Vendor\IWorksIE\Core\Checks\Result;
use WP_UnitTestCase;

/**
 * Settings side effects.
 */
final class SettingsAndUninstallTest extends WP_UnitTestCase {

	/**
	 * @return void
	 */
	public function test_schedule_is_added_and_removed() {
		WeeklyEmail::sync_schedule( true );
		$this->assertNotFalse( wp_next_scheduled( WeeklyEmail::HOOK ) );
		WeeklyEmail::sync_schedule( false );
		$this->assertFalse( wp_next_scheduled( WeeklyEmail::HOOK ) );
	}

	/**
	 * @return void
	 */
	public function test_email_lists_only_problems() {
		$msg = WeeklyEmail::compose(
			array(
				'a' => Result::critical( 'Backups', 'backup.zip is downloadable' ),
				'b' => Result::good( 'HTTPS', 'ok' ),
			)
		);
		$this->assertStringContainsString( 'backup.zip is downloadable', $msg['body'] );
		$this->assertStringNotContainsString( 'HTTPS: ok', $msg['body'] );
		$this->assertStringContainsString( '1 to look at', $msg['subject'] );

		$clear = WeeklyEmail::compose( array( 'b' => Result::good( 'HTTPS', 'ok' ) ) );
		$this->assertSame( '', $clear['issues'] );
	}

	/**
	 * @return void
	 */
	public function test_weekly_run_does_nothing_when_switched_off() {
		update_option( 'iwiesa_settings', array( 'weekly_email' => false ) );
		reset_phpmailer_instance();
		WeeklyEmail::run();
		$mailer = tests_retrieve_phpmailer_instance();
		$this->assertFalse( $mailer->get_sent() );
	}

	/**
	 * @return void
	 */
	public function test_uninstall_removes_options_and_schedule() {
		update_option( 'iwiesa_results', array( 'x' => 1 ) );
		update_option( 'iwiesa_settings', array( 'weekly_email' => true ) );
		update_option( 'iwiesa_wporg_cache', array( 'x' => 1 ) );
		WeeklyEmail::sync_schedule( true );

		if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) ) {
			define( 'WP_UNINSTALL_PLUGIN', 'iworksie-security-audit/iworksie-security-audit.php' );
		}
		include dirname( __DIR__, 2 ) . '/uninstall.php';

		$this->assertFalse( get_option( 'iwiesa_results', false ) );
		$this->assertFalse( get_option( 'iwiesa_settings', false ) );
		$this->assertFalse( get_option( 'iwiesa_wporg_cache', false ) );
		$this->assertFalse( wp_next_scheduled( WeeklyEmail::HOOK ) );
	}
}
