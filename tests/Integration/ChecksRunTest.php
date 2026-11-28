<?php
/**
 * Every check runs cleanly and the exposure logic works end to end.
 *
 * @package IWorksIE\SecurityAudit
 */

namespace IWorksIE\SecurityAudit\Tests\Integration;

use IWorksIE\SecurityAudit\Plugin;
use IWorksIE\SecurityAudit\Vendor\IWorksIE\Core\Checks\Result;
use WP_UnitTestCase;

/**
 * Network requests are answered by a pre_http_request stub.
 */
final class ChecksRunTest extends WP_UnitTestCase {

	/**
	 * URL => [code, body] the stub answers with.
	 *
	 * @var array<string,array{0:int,1:string}>
	 */
	private $responses = array();

	/**
	 * Files created during a test.
	 *
	 * @var array<int,string>
	 */
	private $created = array();

	/**
	 * @return void
	 */
	public function set_up() {
		parent::set_up();
		$this->responses = array();
		add_filter( 'pre_http_request', array( $this, 'fake_http' ), 10, 3 );
	}

	/**
	 * @return void
	 */
	public function tear_down() {
		remove_filter( 'pre_http_request', array( $this, 'fake_http' ), 10 );
		foreach ( $this->created as $file ) {
			if ( file_exists( $file ) ) {
				unlink( $file ); // phpcs:ignore WordPress.WP.AlternativeFunctions.unlink_unlink
			}
		}
		parent::tear_down();
	}

	/**
	 * @param false|array<string,mixed>|\WP_Error $pre  Short-circuit value.
	 * @param array<string,mixed>                 $args Args.
	 * @param string                              $url  URL.
	 * @return array<string,mixed>|\WP_Error
	 */
	public function fake_http( $pre, $args, $url ) {
		unset( $pre, $args );
		foreach ( $this->responses as $prefix => $answer ) {
			if ( 0 === strpos( $url, $prefix ) ) {
				return array(
					'headers'  => array(),
					'body'     => $answer[1],
					'response' => array(
						'code'    => $answer[0],
						'message' => '',
					),
					'cookies'  => array(),
					'filename' => null,
				);
			}
		}
		return new \WP_Error( 'http_request_failed', 'blocked in tests' );
	}

	/**
	 * @param string $name File name in ABSPATH.
	 * @param string $body Contents.
	 * @return string URL.
	 */
	private function make_file( $name, $body ) {
		$path = ABSPATH . $name;
		file_put_contents( $path, $body ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents
		$this->created[] = $path;
		return site_url( '/' . $name );
	}

	/**
	 * @return void
	 */
	public function test_every_check_returns_a_valid_result_offline() {
		$this->assertCount( 22, Plugin::checks() );
		foreach ( Plugin::checks() as $check ) {
			$result = $check->run();
			$this->assertInstanceOf( Result::class, $result, $check->id() );
			$this->assertContains( $result->status(), array( 'good', 'recommended', 'critical', 'info' ), $check->id() );
			$this->assertNotSame( '', $result->description(), $check->id() );
			$this->assertNotSame( '', $result->why(), $check->id() );
		}
	}

	/**
	 * @return void
	 */
	public function test_check_ids_are_unique_and_registered() {
		$core = Plugin::instance()->core();
		$this->assertNotNull( $core );
		$ids = array();
		foreach ( Plugin::checks() as $check ) {
			$ids[] = $check->id();
			$this->assertNotNull( $core->checks()->get( $check->id() ) );
		}
		$this->assertSame( $ids, array_unique( $ids ) );
	}

	/**
	 * @return void
	 */
	public function test_downloadable_config_backup_is_critical() {
		$url                     = $this->make_file( 'wp-config.php.bak', "<?php define( 'DB_NAME', 'x' );" );
		$this->responses[ $url ] = array( 200, "<?php define( 'DB_NAME', 'x' );" );

		$result = ( new \IWorksIE\SecurityAudit\Checks\Exposure\SecretFilesCheck() )->run();
		$this->assertSame( 'critical', $result->status() );
		$data = $result->data();
		$this->assertSame( 'wp-config.php.bak', $data['matches'][0]['relative'] );
	}

	/**
	 * @return void
	 */
	public function test_blocked_file_is_recommended_not_critical() {
		$url                     = $this->make_file( 'iwiesa-test.sql', 'CREATE TABLE x;' );
		$this->responses[ $url ] = array( 403, '<html><body>Forbidden</body></html>' );

		$result = ( new \IWorksIE\SecurityAudit\Checks\Exposure\BackupFilesCheck() )->run();
		$this->assertSame( 'recommended', $result->status() );
	}

	/**
	 * A soft 404 (theme page with status 200) must not be reported as an exposure.
	 *
	 * @return void
	 */
	public function test_soft_404_is_not_critical() {
		$url                     = $this->make_file( 'debug.log', 'PHP Warning: secret path' );
		$this->responses[ $url ] = array( 200, '<!DOCTYPE html><html><head><title>Not found</title></head></html>' );

		$result = ( new \IWorksIE\SecurityAudit\Checks\Exposure\LogFilesCheck() )->run();
		$this->assertSame( 'recommended', $result->status() );
	}

	/**
	 * @return void
	 */
	public function test_closed_plugin_is_flagged() {
		$file = 'hello.php';
		if ( ! file_exists( WP_PLUGIN_DIR . '/' . $file ) ) {
			$this->markTestSkipped( 'Hello Dolly not present in this WP test install.' );
		}
		set_site_transient(
			'update_plugins',
			(object) array(
				'response'  => array(),
				'no_update' => array(
					$file => (object) array(
						'id'   => 'w.org/plugins/hello-dolly',
						'slug' => 'hello-dolly',
					),
				),
			)
		);
		delete_option( 'iwiesa_wporg_cache' );
		$this->responses['https://api.wordpress.org/plugins/info/1.2/'] = array( 404, '{"error":"closed","closed":true,"reason":"security-issue"}' );

		$result = ( new \IWorksIE\SecurityAudit\Checks\Software\AbandonedPluginsCheck() )->run();
		$this->assertSame( 'critical', $result->status() );
	}
}
