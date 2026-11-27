<?php
/**
 * Exposed database dumps and backup archives.
 *
 * @package IWorksIE\SecurityAudit
 */

namespace IWorksIE\SecurityAudit\Checks\Exposure;

use IWorksIE\SecurityAudit\Support\FileExposure;

/**
 * Backup archives and SQL dumps.
 */
final class BackupFilesCheck extends AbstractExposureCheck {

	/** @return string */
	public function id() {
		return 'backup_files';
	}

	/** @return string */
	public function label() {
		return __( 'Backups and database dumps', 'iworksie-security-audit' );
	}

	/** @return string */
	protected function category() {
		return FileExposure::CATEGORY_BACKUPS;
	}

	/** @return string */
	protected function none_found_text() {
		return __( 'No downloadable backups, archives or SQL dumps were found in the website folders.', 'iworksie-security-audit' );
	}

	/** @return string */
	protected function why() {
		return __( 'Bots constantly try names like backup.zip and database.sql. A downloadable backup contains your whole site: customer details, password hashes and the database password.', 'iworksie-security-audit' );
	}

	/** @return string */
	protected function fix() {
		return __( 'Move these files off the web server, or at least out of the website folder. If a backup plugin made them, change its settings so it stores backups in cloud storage or a protected folder.', 'iworksie-security-audit' );
	}
}
