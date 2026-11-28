<?php
/**
 * Shared helpers for Security Audit checks.
 *
 * @package IWorksIE\SecurityAudit
 */

namespace IWorksIE\SecurityAudit\Checks;

use IWorksIE\SecurityAudit\Vendor\IWorksIE\Core\Checks\Check;
use IWorksIE\SecurityAudit\Vendor\IWorksIE\Core\Checks\Result;

/**
 * Every check is read-only: it looks, it never changes anything.
 */
abstract class BaseCheck implements Check {

	/**
	 * Build a Result with the plugin's standard fields.
	 *
	 * @param string                          $status      good|recommended|critical|info.
	 * @param string                          $description What we found.
	 * @param string                          $why         Why it matters.
	 * @param string                          $fix         How to fix.
	 * @param array<string,mixed>             $data        Extra data (e.g. matches).
	 * @param array<int,array<string,string>> $actions     Admin links.
	 * @return Result
	 */
	protected function result( $status, $description, $why, $fix, array $data = array(), array $actions = array() ) {
		$extra = array(
			'why'     => $why,
			'fix'     => $fix,
			'data'    => $data,
			'actions' => $actions,
		);
		switch ( $status ) {
			case 'critical':
				return Result::critical( $this->label(), $description, $extra );
			case 'recommended':
				return Result::recommended( $this->label(), $description, $extra );
			case 'info':
				return Result::info( $this->label(), $description, $extra );
			default:
				return Result::good( $this->label(), $description, $extra );
		}
	}

	/**
	 * "No action needed." in one place.
	 *
	 * @return string
	 */
	protected function no_action() {
		return __( 'No action needed.', 'iworksie-security-audit' );
	}

	/**
	 * Admin action link.
	 *
	 * @param string $label Button text.
	 * @param string $path  Path relative to wp-admin.
	 * @return array{label:string,url:string}
	 */
	protected function action( $label, $path ) {
		return array(
			'label' => $label,
			'url'   => admin_url( $path ),
		);
	}

	/**
	 * Whether this looks like a local or development copy (findings there matter less).
	 *
	 * @return bool
	 */
	protected function is_dev_environment() {
		return function_exists( 'wp_get_environment_type' ) && in_array( wp_get_environment_type(), array( 'local', 'development' ), true );
	}
}
