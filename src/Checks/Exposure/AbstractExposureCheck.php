<?php
/**
 * Base for "can the public download this file?" checks.
 *
 * @package IWorksIE\SecurityAudit
 */

namespace IWorksIE\SecurityAudit\Checks\Exposure;

use IWorksIE\SecurityAudit\Checks\BaseCheck;
use IWorksIE\SecurityAudit\Support\Bytes;
use IWorksIE\SecurityAudit\Support\FileExposure;
use IWorksIE\SecurityAudit\Vendor\IWorksIE\Core\Checks\Result;

/**
 * Finds files on disk, then requests each one like a visitor would.
 */
abstract class AbstractExposureCheck extends BaseCheck {

	/**
	 * FileExposure category.
	 *
	 * @return string
	 */
	abstract protected function category();

	/**
	 * Description when nothing was found.
	 *
	 * @return string
	 */
	abstract protected function none_found_text();

	/**
	 * Why it matters.
	 *
	 * @return string
	 */
	abstract protected function why();

	/**
	 * How to fix an exposed file.
	 *
	 * @return string
	 */
	abstract protected function fix();

	/** @return string */
	public function group() {
		return 'exposure';
	}

	/** @return Result */
	public function run() {
		$audit = FileExposure::audit( $this->category() );

		if ( ! empty( $audit['exposed'] ) ) {
			return $this->result(
				'critical',
				sprintf(
					/* translators: %d: number of files */
					_n(
						'%d item below can be downloaded by anyone who knows its address. We requested it as a logged-out visitor and got the real content back.',
						'%d items below can be downloaded by anyone who knows their address. We requested them as a logged-out visitor and got the real content back.',
						count( $audit['exposed'] ),
						'iworksie-security-audit'
					),
					count( $audit['exposed'] )
				),
				$this->why(),
				$this->fix(),
				array( 'matches' => $this->matches( $audit['exposed'], __( 'Downloadable', 'iworksie-security-audit' ) ) )
			);
		}

		if ( ! empty( $audit['blocked'] ) || ! empty( $audit['unconfirmed'] ) ) {
			$matches     = array_merge(
				$this->matches( $audit['blocked'], __( 'On the server, blocked from download', 'iworksie-security-audit' ) ),
				$this->matches( $audit['unconfirmed'], __( 'On the server, could not test', 'iworksie-security-audit' ) )
			);
			$description = __( 'These files are on the server but could not be downloaded when we tried. They are safe for now, but a server change (new host, lost .htaccess rule) could expose them.', 'iworksie-security-audit' );
			if ( ! empty( $audit['unconfirmed'] ) ) {
				$description = __( 'These files are on the server. Some could not be tested because the site could not request its own pages, or the audit ran out of time.', 'iworksie-security-audit' );
				if ( '' !== $audit['probe_error'] ) {
					$description .= ' ' . sprintf(
						/* translators: %s: error message */
						__( 'Error: %s', 'iworksie-security-audit' ),
						$audit['probe_error']
					);
				}
			}
			return $this->result(
				'recommended',
				$description,
				$this->why(),
				__( 'Move these files out of the website folder (or delete them once you are sure they are not needed). Keep backups somewhere private, such as your computer or cloud storage.', 'iworksie-security-audit' ),
				array( 'matches' => $matches )
			);
		}

		return $this->result( 'good', $this->none_found_text(), $this->why(), $this->no_action() );
	}

	/**
	 * Format files for the result card.
	 *
	 * @param array<int,array<string,mixed>> $items Candidates.
	 * @param string                         $kind  Label.
	 * @return array<int,array<string,string>>
	 */
	protected function matches( array $items, $kind ) {
		$out = array();
		foreach ( $items as $item ) {
			$out[] = array(
				'relative' => (string) $item['relative'],
				'kind'     => $kind,
				'size'     => ! empty( $item['is_dir'] ) ? '' : Bytes::format( (int) $item['bytes'] ),
			);
		}
		return $out;
	}
}
