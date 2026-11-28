<?php
/**
 * Plugin-specific AJAX endpoints.
 *
 * @package IWorksIE\SecurityAudit
 */

namespace IWorksIE\SecurityAudit\Admin;

use IWorksIE\SecurityAudit\Support\ResultsCache;
use IWorksIE\SecurityAudit\Vendor\IWorksIE\Core\Checks\Result;
use IWorksIE\SecurityAudit\Vendor\IWorksIE\Core\Core;
use IWorksIE\SecurityAudit\Vendor\IWorksIE\Core\Strings;

/**
 * Run one check (results stored server-side) and stamp the run time.
 */
final class Ajax {

	/**
	 * @var Core
	 */
	private $core;

	/**
	 * @param Core $core Core.
	 */
	public function __construct( Core $core ) {
		$this->core = $core;
	}

	/**
	 * @return void
	 */
	public function hooks() {
		// Priority 5 so this runs (and exits) before core's generic iwiesa_run_check handler.
		add_action( 'wp_ajax_iwiesa_run_check', array( $this, 'run_check' ), 5 );
		add_action( 'wp_ajax_iwiesa_finish_audit', array( $this, 'finish_audit' ) );
	}

	/**
	 * @return void
	 */
	public function run_check() {
		check_ajax_referer( 'iwiesa_checks', 'nonce' );
		if ( ! current_user_can( (string) $this->core->config( 'capability' ) ) ) {
			wp_send_json_error( array( 'message' => 'forbidden' ), 403 );
		}

		$id    = isset( $_POST['check_id'] ) ? sanitize_key( wp_unslash( (string) $_POST['check_id'] ) ) : '';
		$check = $this->core->checks()->get( $id );
		if ( null === $check ) {
			wp_send_json_error( array( 'message' => 'unknown_check' ), 404 );
		}

		try {
			$result = $check->run();
		} catch ( \Throwable $e ) {
			$result = Result::critical(
				$check->label(),
				Strings::get( 'check_failed', array( 'message' => $e->getMessage() ) )
			);
		}

		$payload = $result->to_array();
		ResultsCache::save_one( $id, $payload );
		wp_send_json_success( ResultsCache::sanitize_result( $payload ) );
	}

	/**
	 * Stamp "last audited" after a full run. Accepts no results from the browser.
	 *
	 * @return void
	 */
	public function finish_audit() {
		check_ajax_referer( 'iwiesa_checks', 'nonce' );
		if ( ! current_user_can( (string) $this->core->config( 'capability' ) ) ) {
			wp_send_json_error( array( 'message' => 'forbidden' ), 403 );
		}
		ResultsCache::touch();
		wp_send_json_success( array( 'last_checked' => ResultsCache::last_checked_label() ) );
	}
}
