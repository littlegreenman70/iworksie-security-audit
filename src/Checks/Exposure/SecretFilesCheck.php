<?php
/**
 * Exposed wp-config copies, .env, .htpasswd and phpinfo pages.
 *
 * @package IWorksIE\SecurityAudit
 */

namespace IWorksIE\SecurityAudit\Checks\Exposure;

use IWorksIE\SecurityAudit\Support\FileExposure;

/**
 * Secret and configuration files.
 */
final class SecretFilesCheck extends AbstractExposureCheck {

	/** @return string */
	public function id() {
		return 'secret_files';
	}

	/** @return string */
	public function label() {
		return __( 'Config and password files', 'iworksie-security-audit' );
	}

	/** @return string */
	protected function category() {
		return FileExposure::CATEGORY_SECRETS;
	}

	/** @return string */
	protected function none_found_text() {
		return __( 'No copies of wp-config.php, .env, .htpasswd or phpinfo pages were found in the website folders.', 'iworksie-security-audit' );
	}

	/** @return string */
	protected function why() {
		return __( 'A copy such as wp-config.php.bak is sent as plain text instead of being run, so it hands over your database password and secret keys. A phpinfo page shows server paths and settings attackers use to plan an attack.', 'iworksie-security-audit' );
	}

	/** @return string */
	protected function fix() {
		return __( 'Delete these files from the server today (download a copy first if you need one). Then change your database password and generate new security keys in wp-config.php, because the old ones may already have been copied.', 'iworksie-security-audit' );
	}
}
