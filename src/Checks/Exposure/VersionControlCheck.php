<?php
/**
 * Exposed .git / .svn / .hg folders.
 *
 * @package IWorksIE\SecurityAudit
 */

namespace IWorksIE\SecurityAudit\Checks\Exposure;

use IWorksIE\SecurityAudit\Support\FileExposure;

/**
 * Version control metadata.
 */
final class VersionControlCheck extends AbstractExposureCheck {

	/** @return string */
	public function id() {
		return 'version_control';
	}

	/** @return string */
	public function label() {
		return __( 'Git and SVN folders', 'iworksie-security-audit' );
	}

	/** @return string */
	protected function category() {
		return FileExposure::CATEGORY_VCS;
	}

	/** @return string */
	protected function none_found_text() {
		return __( 'No .git, .svn or .hg folders were found in the website folders.', 'iworksie-security-audit' );
	}

	/** @return string */
	protected function why() {
		return __( 'Free tools can rebuild your entire code history from a public .git folder, including any passwords or API keys that were ever committed.', 'iworksie-security-audit' );
	}

	/** @return string */
	protected function fix() {
		return __( 'Ask your developer to deploy without the .git folder, or block it in the server configuration (for Apache: RedirectMatch 404 /\.git). Change any passwords that were ever stored in the code.', 'iworksie-security-audit' );
	}
}
