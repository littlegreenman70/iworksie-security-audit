<?php
/**
 * PHP version still getting security fixes.
 *
 * @package IWorksIE\SecurityAudit
 */

namespace IWorksIE\SecurityAudit\Checks\Software;

use IWorksIE\SecurityAudit\Checks\BaseCheck;
use IWorksIE\SecurityAudit\Support\PhpEol;
use IWorksIE\SecurityAudit\Vendor\IWorksIE\Core\Checks\Result;

/**
 * PHP end-of-life.
 */
final class PhpVersionCheck extends BaseCheck {

	/** @return string */
	public function id() {
		return 'php_version';
	}

	/** @return string */
	public function label() {
		return __( 'PHP version', 'iworksie-security-audit' );
	}

	/** @return string */
	public function group() {
		return 'software';
	}

	/** @return Result */
	public function run() {
		$version = PHP_VERSION;
		$status  = PhpEol::classify( $version );
		$why     = __( 'PHP is the language WordPress runs on. Once a PHP version reaches end of life, newly found security holes in it are never fixed.', 'iworksie-security-audit' );
		$fix     = __( 'Ask your host to move the site to a supported PHP version (8.3 or newer is a good target). Most hosts have a PHP switch in their control panel. Take a backup first.', 'iworksie-security-audit' );
		$data    = array( 'version' => $version );

		if ( 'critical' === $status ) {
			return $this->result(
				'critical',
				/* translators: %s: PHP version */
				sprintf( __( 'PHP %s no longer gets security fixes.', 'iworksie-security-audit' ), $version ),
				$why,
				$fix,
				$data
			);
		}
		if ( 'recommended' === $status ) {
			return $this->result(
				'recommended',
				/* translators: %s: PHP version */
				sprintf( __( 'PHP %s only gets security fixes now and will reach end of life soon.', 'iworksie-security-audit' ), $version ),
				$why,
				$fix,
				$data
			);
		}
		return $this->result(
			'good',
			/* translators: %s: PHP version */
			sprintf( __( 'PHP %s is fully supported.', 'iworksie-security-audit' ), $version ),
			$why,
			$this->no_action(),
			$data
		);
	}
}
