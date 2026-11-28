<?php
/**
 * AJAX guards and server-side result storage.
 *
 * @package IWorksIE\SecurityAudit
 */

namespace IWorksIE\SecurityAudit\Tests\Integration;

use WP_Ajax_UnitTestCase;

/**
 * Uses the WP AJAX test harness.
 */
final class AjaxTest extends WP_Ajax_UnitTestCase {

	/**
	 * @return void
	 */
	public function test_run_check_rejects_bad_nonce() {
		$this->_setRole( 'administrator' );
		$_POST['nonce']    = 'bad';
		$_POST['check_id'] = 'file_editor';
		try {
			$this->_handleAjax( 'iwiesa_run_check' );
			$this->fail( 'Expected ajax die for bad nonce' );
		} catch ( \WPAjaxDieStopException $e ) {
			$this->assertSame( '-1', $e->getMessage() );
		}
	}

	/**
	 * @return void
	 */
	public function test_run_check_rejects_subscriber() {
		$this->_setRole( 'subscriber' );
		$_POST['nonce']    = wp_create_nonce( 'iwiesa_checks' );
		$_POST['check_id'] = 'file_editor';
		try {
			$this->_handleAjax( 'iwiesa_run_check' );
		} catch ( \WPAjaxDieContinueException $e ) {
			unset( $e );
		} catch ( \WPAjaxDieStopException $e ) {
			unset( $e );
		}
		$response = json_decode( (string) $this->_last_response, true );
		$this->assertFalse( is_array( $response ) && ! empty( $response['success'] ) );
		$this->assertFalse( get_option( 'iwiesa_results', false ) );
	}

	/**
	 * @return void
	 */
	public function test_admin_run_check_stores_result() {
		$this->_setRole( 'administrator' );
		if ( is_multisite() ) {
			grant_super_admin( get_current_user_id() );
		}
		$_POST['nonce']    = wp_create_nonce( 'iwiesa_checks' );
		$_POST['check_id'] = 'file_editor';
		try {
			$this->_handleAjax( 'iwiesa_run_check' );
		} catch ( \WPAjaxDieContinueException $e ) {
			unset( $e );
		}
		$response = json_decode( (string) $this->_last_response, true );
		$this->assertTrue( $response['success'] );
		$this->assertContains( $response['data']['status'], array( 'good', 'recommended' ) );

		$stored = get_option( 'iwiesa_results' );
		$this->assertIsArray( $stored );
		$this->assertArrayHasKey( 'file_editor', $stored['results'] );
	}
}
