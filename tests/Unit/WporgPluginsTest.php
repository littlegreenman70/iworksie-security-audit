<?php
/**
 * WordPress.org API response parsing.
 *
 * @package IWorksIE\SecurityAudit
 */

namespace IWorksIE\SecurityAudit\Tests\Unit;

use Brain\Monkey;
use Brain\Monkey\Functions;
use IWorksIE\SecurityAudit\Support\WporgPlugins;
use PHPUnit\Framework\TestCase;

/**
 * @covers \IWorksIE\SecurityAudit\Support\WporgPlugins
 */
final class WporgPluginsTest extends TestCase {

	protected function setUp(): void {
		parent::setUp();
		Monkey\setUp();
		Functions\when( 'sanitize_key' )->alias(
			static function ( $key ) {
				return preg_replace( '/[^a-z0-9_\-]/', '', strtolower( (string) $key ) );
			}
		);
	}

	protected function tearDown(): void {
		Monkey\tearDown();
		parent::tearDown();
	}

	public function test_open_plugin() {
		$out = WporgPlugins::parse( 200, '{"name":"Akismet","slug":"akismet","version":"5.3","last_updated":"2024-11-12 4:38pm GMT"}' );
		$this->assertSame( 'ok', $out['status'] );
		$this->assertSame( gmmktime( 16, 38, 0, 11, 12, 2024 ), $out['last_updated'] );
	}

	public function test_closed_plugin_with_reason() {
		$out = WporgPlugins::parse( 404, '{"error":"closed","name":"Old","slug":"old","closed":true,"closed_date":"2023-05-01","reason":"security-issue","reason_text":"Security Issue"}' );
		$this->assertSame( 'closed', $out['status'] );
		$this->assertSame( 'security-issue', $out['reason'] );
	}

	public function test_not_on_wporg() {
		$out = WporgPlugins::parse( 404, '{"error":"Plugin not found."}' );
		$this->assertSame( 'missing', $out['status'] );
	}

	public function test_garbage_is_unknown() {
		$this->assertSame( 'unknown', WporgPlugins::parse( 502, '<html>Bad gateway</html>' )['status'] );
		$this->assertSame( 'unknown', WporgPlugins::parse( 500, '{"foo":1}' )['status'] );
	}
}
