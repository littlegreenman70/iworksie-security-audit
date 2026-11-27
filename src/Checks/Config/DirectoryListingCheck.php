<?php
/**
 * Folder listings switched on (e.g. /wp-content/uploads/ shows every file).
 *
 * @package IWorksIE\SecurityAudit
 */

namespace IWorksIE\SecurityAudit\Checks\Config;

use IWorksIE\SecurityAudit\Checks\BaseCheck;
use IWorksIE\SecurityAudit\Support\Probe;
use IWorksIE\SecurityAudit\Vendor\IWorksIE\Core\Checks\Result;

/**
 * Requests the uploads folder and looks for an "Index of" page.
 */
final class DirectoryListingCheck extends BaseCheck {

	/** @return string */
	public function id() {
		return 'directory_listing';
	}

	/** @return string */
	public function label() {
		return __( 'Folder listings', 'iworksie-security-audit' );
	}

	/** @return string */
	public function group() {
		return 'exposure';
	}

	/** @return Result */
	public function run() {
		$why = __( 'When folder listings are on, anyone can browse a list of every file in a folder, including private uploads, invoices and forgotten backups.', 'iworksie-security-audit' );
		$fix = __( 'Turn off directory indexes on the server. For Apache add "Options -Indexes" to the .htaccess file in the website folder; on Nginx make sure "autoindex" is off. Your host can do this for you.', 'iworksie-security-audit' );

		$uploads = wp_get_upload_dir();
		$urls    = array();
		if ( empty( $uploads['error'] ) && ! empty( $uploads['baseurl'] ) ) {
			$urls[] = trailingslashit( (string) $uploads['baseurl'] );
		}
		$urls[] = trailingslashit( includes_url() ) . 'css/';

		$listed = array();
		$error  = '';
		foreach ( $urls as $url ) {
			$response = Probe::fetch( $url );
			if ( ! $response['reachable'] ) {
				$error = $response['error'];
				continue;
			}
			if ( Probe::is_ok( $response ) && self::is_listing( $response['body'] ) ) {
				$listed[] = array(
					'relative' => (string) wp_parse_url( $url, PHP_URL_PATH ),
					'kind'     => __( 'Listing visible', 'iworksie-security-audit' ),
				);
			}
		}

		if ( ! empty( $listed ) ) {
			return $this->result(
				'recommended',
				__( 'Folder listings are switched on: visiting a folder address shows a list of every file in it.', 'iworksie-security-audit' ),
				$why,
				$fix,
				array( 'matches' => $listed )
			);
		}
		if ( '' !== $error ) {
			return $this->result(
				'info',
				sprintf(
					/* translators: %s: error message */
					__( 'Could not test: the site could not request its own pages (%s).', 'iworksie-security-audit' ),
					$error
				),
				$why,
				__( 'Open your uploads folder address (for example /wp-content/uploads/) in a private browser window. If you see a list of files, follow the fix below.', 'iworksie-security-audit' ) . ' ' . $fix
			);
		}
		return $this->result( 'good', __( 'Folder listings are switched off.', 'iworksie-security-audit' ), $why, $this->no_action() );
	}

	/**
	 * Whether a page body is an auto-generated folder index. Pure function.
	 *
	 * @param string $body Body prefix.
	 * @return bool
	 */
	public static function is_listing( $body ) {
		return 1 === preg_match( '/<title>\s*(Index of|Directory listing for)\s/i', (string) $body )
			|| 1 === preg_match( '/<h1>\s*Index of\s+\//i', (string) $body );
	}
}
