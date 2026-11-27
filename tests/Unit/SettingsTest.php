<?php
/**
 * Settings sanitising.
 *
 * @package IWorksIE\SecurityAudit
 */

namespace IWorksIE\SecurityAudit\Tests\Unit;

use Brain\Monkey;
use Brain\Monkey\Functions;
use IWorksIE\SecurityAudit\Support\Settings;
use PHPUnit\Framework\TestCase;

/**
 * @covers \IWorksIE\SecurityAudit\Support\Settings
 */
final class SettingsTest extends TestCase {

	protected function setUp(): void {
		parent::setUp();
		Monkey\setUp();
		Functions\when( 'sanitize_email' )->alias(
			static function ( $email ) {
				return trim( (string) $email );
			}
		);
		Functions\when( 'is_email' )->alias(
			static function ( $email ) {
				return false !== filter_var( $email, FILTER_VALIDATE_EMAIL ) ? $email : false;
			}
		);
	}

	protected function tearDown(): void {
		Monkey\tearDown();
		parent::tearDown();
	}

	public function test_defaults_are_off_and_quiet() {
		$out = Settings::sanitize( array() );
		$this->assertFalse( $out['weekly_email'] );
		$this->assertTrue( $out['only_issues'] );
		$this->assertSame( '', $out['email'] );
	}

	public function test_invalid_email_is_dropped() {
		$out = Settings::sanitize(
			array(
				'weekly_email' => '1',
				'only_issues'  => false,
				'email'        => 'not an email',
			)
		);
		$this->assertTrue( $out['weekly_email'] );
		$this->assertFalse( $out['only_issues'] );
		$this->assertSame( '', $out['email'] );
	}

	public function test_valid_email_kept() {
		$out = Settings::sanitize( array( 'email' => 'ops@example.ie' ) );
		$this->assertSame( 'ops@example.ie', $out['email'] );
	}
}
