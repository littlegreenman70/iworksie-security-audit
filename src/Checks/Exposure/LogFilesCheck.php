<?php
/**
 * Exposed debug.log / error_log files.
 *
 * @package IWorksIE\SecurityAudit
 */

namespace IWorksIE\SecurityAudit\Checks\Exposure;

use IWorksIE\SecurityAudit\Support\FileExposure;

/**
 * Log files.
 */
final class LogFilesCheck extends AbstractExposureCheck {

	/** @return string */
	public function id() {
		return 'log_files';
	}

	/** @return string */
	public function label() {
		return __( 'Log files', 'iworksie-security-audit' );
	}

	/** @return string */
	protected function category() {
		return FileExposure::CATEGORY_LOGS;
	}

	/** @return string */
	protected function none_found_text() {
		return __( 'No debug.log, error_log or other log files were found in the website folders.', 'iworksie-security-audit' );
	}

	/** @return string */
	protected function why() {
		return __( 'wp-content/debug.log is public by default. Logs reveal server paths, plugin names and sometimes email addresses or form data, which helps attackers.', 'iworksie-security-audit' );
	}

	/** @return string */
	protected function fix() {
		return __( 'Delete the log files. If you need debug logging, set WP_DEBUG_LOG in wp-config.php to a path outside the website folder, for example define( \'WP_DEBUG_LOG\', \'/home/you/logs/wp-debug.log\' );', 'iworksie-security-audit' );
	}
}
