<?php
/**
 * Theme/plugin file editor enabled.
 *
 * @package IWorksIE\SecurityAudit
 */

namespace IWorksIE\SecurityAudit\Checks\Config;

use IWorksIE\SecurityAudit\Checks\BaseCheck;
use IWorksIE\SecurityAudit\Vendor\IWorksIE\Core\Checks\Result;

/**
 * DISALLOW_FILE_EDIT / DISALLOW_FILE_MODS.
 */
final class FileEditorCheck extends BaseCheck {

	/** @return string */
	public function id() {
		return 'file_editor';
	}

	/** @return string */
	public function label() {
		return __( 'Plugin and theme code editor', 'iworksie-security-audit' );
	}

	/** @return string */
	public function group() {
		return 'config';
	}

	/** @return Result */
	public function run() {
		$blocked = ( defined( 'DISALLOW_FILE_EDIT' ) && DISALLOW_FILE_EDIT ) || ( defined( 'DISALLOW_FILE_MODS' ) && DISALLOW_FILE_MODS );
		$why     = __( 'The built-in editor lets anyone logged in as an administrator change PHP code from the browser. If one admin password is stolen, this is the quickest way to plant malware.', 'iworksie-security-audit' );

		if ( $blocked ) {
			return $this->result( 'good', __( 'The code editor is switched off.', 'iworksie-security-audit' ), $why, $this->no_action() );
		}
		return $this->result(
			'recommended',
			__( 'The plugin and theme code editor is switched on.', 'iworksie-security-audit' ),
			$why,
			__( 'Add define( \'DISALLOW_FILE_EDIT\', true ); to wp-config.php, above the line that says "That\'s all, stop editing!". Edit code by SFTP or Git instead.', 'iworksie-security-audit' )
		);
	}
}
