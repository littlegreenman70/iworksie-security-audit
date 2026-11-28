<?php
/**
 * File classification and download signatures.
 *
 * @package IWorksIE\SecurityAudit
 */

namespace IWorksIE\SecurityAudit\Tests\Unit;

use IWorksIE\SecurityAudit\Support\FileExposure;
use PHPUnit\Framework\TestCase;

/**
 * @covers \IWorksIE\SecurityAudit\Support\FileExposure
 */
final class FileExposureTest extends TestCase {

	/**
	 * @return array<string,array{0:string,1:bool,2:string|null,3:string|null}>
	 */
	public function names() {
		return array(
			'wp-config backup'       => array( 'wp-config.php.bak', false, 'secrets', 'wpconfig' ),
			'wp-config tilde'        => array( 'wp-config.php~', false, 'secrets', 'wpconfig' ),
			'vim swap'               => array( '.wp-config.php.swp', false, 'secrets', 'wpconfig' ),
			'wp-config.txt'          => array( 'wp-config.txt', false, 'secrets', 'wpconfig' ),
			'wp-config itself'       => array( 'wp-config.php', false, null, null ),
			'wp-config sample'       => array( 'wp-config-sample.php', false, null, null ),
			'wp-config php copy'     => array( 'wp-config-old.php', false, null, null ),
			'.env'                   => array( '.env', false, 'secrets', 'env' ),
			'.env.production'        => array( '.env.production', false, 'secrets', 'env' ),
			'.env.example'           => array( '.env.example', false, null, null ),
			'.htpasswd'              => array( '.htpasswd', false, 'secrets', 'htpasswd' ),
			'phpinfo'                => array( 'phpinfo.php', false, 'secrets', 'phpinfo' ),
			'debug log'              => array( 'debug.log', false, 'logs', 'log' ),
			'error_log'              => array( 'error_log', false, 'logs', 'log' ),
			'sql'                    => array( 'database.sql', false, 'backups', 'sql' ),
			'sql.gz'                 => array( 'site-2024.sql.gz', false, 'backups', 'gzip' ),
			'zip'                    => array( 'Backup.ZIP', false, 'backups', 'zip' ),
			'tar.gz'                 => array( 'site.tar.gz', false, 'backups', 'gzip' ),
			'wpress'                 => array( 'site-20240101.wpress', false, 'backups', 'any' ),
			'php.bak'                => array( 'index.php.bak', false, 'backups', 'any' ),
			'git dir'                => array( '.git', true, 'vcs', 'git_head' ),
			'svn dir'                => array( '.svn', true, 'vcs', 'svn_db' ),
			'git file not dir'       => array( '.git', false, null, null ),
			'normal folder'          => array( 'uploads', true, null, null ),
			'normal php'             => array( 'index.php', false, null, null ),
			'htaccess'               => array( '.htaccess', false, null, null ),
		);
	}

	/**
	 * @dataProvider names
	 *
	 * @param string      $name      File name.
	 * @param bool        $is_dir    Directory?
	 * @param string|null $category  Expected category.
	 * @param string|null $signature Expected signature.
	 */
	public function test_classify_name( $name, $is_dir, $category, $signature ) {
		$rule = FileExposure::classify_name( $name, $is_dir );
		if ( null === $category ) {
			$this->assertNull( $rule );
			return;
		}
		$this->assertNotNull( $rule );
		$this->assertSame( $category, $rule['category'] );
		$this->assertSame( $signature, $rule['signature'] );
	}

	public function test_git_probe_reads_head() {
		$rule = FileExposure::classify_name( '.git', true );
		$this->assertSame( '/HEAD', $rule['probe_suffix'] );
	}

	public function test_soft_404_html_is_not_an_exposure() {
		$page = "<!DOCTYPE html>\n<html><head><title>Page not found</title></head><body>DB_NAME</body></html>";
		$this->assertFalse( FileExposure::matches_signature( 'env', $page ) );
		$this->assertFalse( FileExposure::matches_signature( 'sql', $page ) );
		$this->assertFalse( FileExposure::matches_signature( 'any', $page ) );
		$this->assertFalse( FileExposure::matches_signature( 'log', $page ) );
		$this->assertFalse( FileExposure::matches_signature( 'zip', $page ) );
		$this->assertFalse( FileExposure::matches_signature( 'git_head', $page ) );
	}

	public function test_real_files_match() {
		$this->assertTrue( FileExposure::matches_signature( 'wpconfig', "<?php\ndefine( 'DB_NAME', 'x' );" ) );
		$this->assertTrue( FileExposure::matches_signature( 'env', "APP_KEY=abc\nDB_PASSWORD=secret\n" ) );
		$this->assertTrue( FileExposure::matches_signature( 'htpasswd', "admin:\$apr1\$abc\$def\n" ) );
		$this->assertTrue( FileExposure::matches_signature( 'git_head', "ref: refs/heads/main\n" ) );
		$this->assertTrue( FileExposure::matches_signature( 'svn_db', "SQLite format 3\0..." ) );
		$this->assertTrue( FileExposure::matches_signature( 'sql', "-- MySQL dump 10.13\nCREATE TABLE `wp_posts`" ) );
		$this->assertTrue( FileExposure::matches_signature( 'zip', "PK\x03\x04rest" ) );
		$this->assertTrue( FileExposure::matches_signature( 'gzip', "\x1f\x8b\x08rest" ) );
		$this->assertTrue( FileExposure::matches_signature( 'tar', str_repeat( "\0", 257 ) . 'ustar  ' ) );
		$this->assertTrue( FileExposure::matches_signature( 'log', "[01-Jan-2026 10:00:00 UTC] PHP Warning: x\n" ) );
		$this->assertTrue( FileExposure::matches_signature( 'phpinfo', '<!DOCTYPE html><html><title>phpinfo()</title>' ) );
	}

	public function test_empty_body_never_matches() {
		$this->assertFalse( FileExposure::matches_signature( 'any', '' ) );
		$this->assertFalse( FileExposure::matches_signature( 'log', "  \n" ) );
	}

	public function test_wrong_magic_bytes_do_not_match() {
		$this->assertFalse( FileExposure::matches_signature( 'zip', 'Not a zip' ) );
		$this->assertFalse( FileExposure::matches_signature( 'gzip', 'plain text' ) );
		$this->assertFalse( FileExposure::matches_signature( 'wpconfig', 'Forbidden' ) );
	}
}
