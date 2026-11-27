<?php
/**
 * Pure helpers inside checks.
 *
 * @package IWorksIE\SecurityAudit
 */

namespace IWorksIE\SecurityAudit\Tests\Unit;

use Brain\Monkey;
use Brain\Monkey\Functions;
use IWorksIE\SecurityAudit\Checks\Access\AdminUsernameCheck;
use IWorksIE\SecurityAudit\Checks\Access\LoginProtectionCheck;
use IWorksIE\SecurityAudit\Checks\Access\UserEnumerationCheck;
use IWorksIE\SecurityAudit\Checks\Config\DebugDisplayCheck;
use IWorksIE\SecurityAudit\Checks\Config\DirectoryListingCheck;
use IWorksIE\SecurityAudit\Checks\Config\SecurityKeysCheck;
use IWorksIE\SecurityAudit\Checks\Server\FilePermissionsCheck;
use IWorksIE\SecurityAudit\Checks\Server\SecurityHeadersCheck;
use IWorksIE\SecurityAudit\Checks\Software\CoreUpdatesCheck;
use PHPUnit\Framework\TestCase;

/**
 * @coversNothing
 */
final class PureChecksTest extends TestCase {

	protected function setUp(): void {
		parent::setUp();
		Monkey\setUp();
		Functions\stubTranslationFunctions();
	}

	protected function tearDown(): void {
		Monkey\tearDown();
		parent::tearDown();
	}

	public function test_security_keys_problems() {
		$good = str_repeat( 'a', 40 );
		$out  = SecurityKeysCheck::problems(
			array(
				'AUTH_KEY'        => 'put your unique phrase here',
				'SECURE_AUTH_KEY' => 'short',
				'LOGGED_IN_KEY'   => null,
				'NONCE_KEY'       => $good,
				'AUTH_SALT'       => $good,
				'SECURE_AUTH_SALT' => str_repeat( 'b', 64 ),
			)
		);
		$this->assertSame( array( 'AUTH_KEY' ), $out['default'] );
		$this->assertSame( array( 'SECURE_AUTH_KEY' ), $out['weak'] );
		$this->assertSame( array( 'LOGGED_IN_KEY' ), $out['missing'] );
		$this->assertSame( array( 'NONCE_KEY', 'AUTH_SALT' ), $out['duplicate'] );
	}

	public function test_guessable_admin_names() {
		$this->assertSame( array( 'Admin', 'example' ), AdminUsernameCheck::guessable( array( 'Admin', 'cormac_r', 'example' ), 'www.example.ie' ) );
		$this->assertSame( array(), AdminUsernameCheck::guessable( array( 'jane-ops' ), 'example.ie' ) );
	}

	public function test_login_protection_detects_folder() {
		$found = LoginProtectionCheck::detect( array( 'akismet/akismet.php', 'two-factor/two-factor.php', 'Wordfence/wordfence.php' ), LoginProtectionCheck::KNOWN );
		$this->assertSame( array( 'Two Factor', 'Wordfence' ), $found );
		$this->assertSame( array(), LoginProtectionCheck::detect( array( 'hello.php' ), LoginProtectionCheck::KNOWN ) );
	}

	public function test_rest_slugs() {
		$this->assertSame( array( 'admin', 'jane' ), UserEnumerationCheck::slugs_from_rest( 200, '[{"id":1,"slug":"admin"},{"id":2,"slug":"jane"}]' ) );
		$this->assertSame( array(), UserEnumerationCheck::slugs_from_rest( 401, '{"code":"rest_forbidden"}' ) );
		$this->assertSame( array(), UserEnumerationCheck::slugs_from_rest( 200, '[]' ) );
		// Body cut off at the read limit.
		$this->assertSame( array( 'admin' ), UserEnumerationCheck::slugs_from_rest( 200, '[{"id":1,"slug":"admin","avatar_urls":{"24":"ht' ) );
	}

	public function test_author_redirect() {
		$this->assertSame( 'jane', UserEnumerationCheck::slug_from_author_redirect( 301, 'https://example.ie/author/jane/' ) );
		$this->assertSame( '', UserEnumerationCheck::slug_from_author_redirect( 200, 'https://example.ie/author/jane/' ) );
		$this->assertSame( '', UserEnumerationCheck::slug_from_author_redirect( 301, 'https://example.ie/' ) );
	}

	public function test_directory_listing_detection() {
		$this->assertTrue( DirectoryListingCheck::is_listing( '<html><head><title>Index of /wp-content/uploads</title>' ) );
		$this->assertTrue( DirectoryListingCheck::is_listing( '<title>Directory listing for /</title>' ) );
		$this->assertFalse( DirectoryListingCheck::is_listing( '<title>My blog</title>' ) );
	}

	public function test_world_writable() {
		$this->assertTrue( FilePermissionsCheck::is_world_writable( 0100777 ) );
		$this->assertTrue( FilePermissionsCheck::is_world_writable( 0100666 ) );
		$this->assertFalse( FilePermissionsCheck::is_world_writable( 0100644 ) );
		$this->assertFalse( FilePermissionsCheck::is_world_writable( 040755 ) );
		$this->assertSame( '0777', FilePermissionsCheck::octal( 040777 ) );
	}

	public function test_security_headers() {
		$missing = SecurityHeadersCheck::missing( array(), true );
		$this->assertArrayHasKey( 'Strict-Transport-Security', $missing );
		$this->assertCount( 4, $missing );

		$this->assertArrayNotHasKey( 'Strict-Transport-Security', SecurityHeadersCheck::missing( array(), false ) );

		$all = array(
			'strict-transport-security' => 'max-age=31536000',
			'x-content-type-options'    => 'nosniff',
			'content-security-policy'   => "frame-ancestors 'self'",
			'referrer-policy'           => 'strict-origin-when-cross-origin',
		);
		$this->assertSame( array(), SecurityHeadersCheck::missing( $all, true ) );
		$this->assertSame( 'X-Powered-By: PHP/8.1.2', SecurityHeadersCheck::version_leak( array( 'x-powered-by' => 'PHP/8.1.2' ) ) );
		$this->assertSame( '', SecurityHeadersCheck::version_leak( array( 'x-powered-by' => 'Express' ) ) );
	}

	public function test_core_latest_offer() {
		$updates = array(
			(object) array(
				'response' => 'latest',
				'current'  => '6.8.1',
			),
			(object) array(
				'response' => 'upgrade',
				'current'  => '6.8.3',
			),
			array(
				'response' => 'upgrade',
				'current'  => '6.8.2',
			),
		);
		$this->assertSame( '6.8.3', CoreUpdatesCheck::latest_offer( $updates ) );
		$this->assertSame( '', CoreUpdatesCheck::latest_offer( array() ) );
	}

	public function test_core_branch_comparison() {
		$this->assertTrue( CoreUpdatesCheck::same_branch( '6.8.1', '6.8.3' ) );
		$this->assertFalse( CoreUpdatesCheck::same_branch( '6.8.3', '6.9' ) );
		$this->assertFalse( CoreUpdatesCheck::same_branch( '6.9.1', '7.0.2' ) );
	}

	public function test_display_errors_values() {
		$this->assertTrue( DebugDisplayCheck::display_errors_on( 'On' ) );
		$this->assertTrue( DebugDisplayCheck::display_errors_on( '1' ) );
		$this->assertTrue( DebugDisplayCheck::display_errors_on( 'stderr' ) );
		$this->assertFalse( DebugDisplayCheck::display_errors_on( '' ) );
		$this->assertFalse( DebugDisplayCheck::display_errors_on( 'Off' ) );
		$this->assertFalse( DebugDisplayCheck::display_errors_on( '0' ) );
	}
}
