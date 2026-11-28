<?php
/**
 * Site served over HTTPS.
 *
 * @package IWorksIE\SecurityAudit
 */

namespace IWorksIE\SecurityAudit\Checks\Config;

use IWorksIE\SecurityAudit\Checks\BaseCheck;
use IWorksIE\SecurityAudit\Vendor\IWorksIE\Core\Checks\Result;

/**
 * Home / site URL scheme and admin SSL.
 */
final class HttpsCheck extends BaseCheck {

	/** @return string */
	public function id() {
		return 'https';
	}

	/** @return string */
	public function label() {
		return __( 'HTTPS', 'iworksie-security-audit' );
	}

	/** @return string */
	public function group() {
		return 'config';
	}

	/** @return Result */
	public function run() {
		$home = 'https' === wp_parse_url( home_url(), PHP_URL_SCHEME );
		$site = 'https' === wp_parse_url( site_url(), PHP_URL_SCHEME );
		$why  = __( 'Without HTTPS, passwords and login cookies travel unencrypted. Anyone on the same Wi-Fi or network path can read them.', 'iworksie-security-audit' );

		if ( $home && $site ) {
			return $this->result( 'good', __( 'The site and admin use HTTPS.', 'iworksie-security-audit' ), $why, $this->no_action() );
		}
		$fix = __( 'Ask your host for a free SSL certificate (most offer Let\'s Encrypt), then change both addresses under Settings > General to start with https://. Take a backup first.', 'iworksie-security-audit' );
		if ( $this->is_dev_environment() ) {
			return $this->result( 'info', __( 'This local or development copy does not use HTTPS. That is fine here, but the live site must.', 'iworksie-security-audit' ), $why, $fix );
		}
		return $this->result(
			'critical',
			__( 'The site address does not use HTTPS, so logins are sent unencrypted.', 'iworksie-security-audit' ),
			$why,
			$fix,
			array(),
			array( $this->action( __( 'Open General Settings', 'iworksie-security-audit' ), 'options-general.php' ) )
		);
	}
}
