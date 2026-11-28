<?php
/**
 * WordPress core version.
 *
 * @package IWorksIE\SecurityAudit
 */

namespace IWorksIE\SecurityAudit\Checks\Software;

use IWorksIE\SecurityAudit\Checks\BaseCheck;
use IWorksIE\SecurityAudit\Vendor\IWorksIE\Core\Checks\Result;

/**
 * Reads WordPress's own update data (no extra requests).
 */
final class CoreUpdatesCheck extends BaseCheck {

	/** @return string */
	public function id() {
		return 'core_updates';
	}

	/** @return string */
	public function label() {
		return __( 'WordPress version', 'iworksie-security-audit' );
	}

	/** @return string */
	public function group() {
		return 'software';
	}

	/** @return Result */
	public function run() {
		$current   = (string) get_bloginfo( 'version' );
		$transient = get_site_transient( 'update_core' );
		$why       = __( 'Each WordPress release fixes security problems that are then made public. Sites that stay behind are the easiest targets.', 'iworksie-security-audit' );
		$actions   = array( $this->action( __( 'Open Updates', 'iworksie-security-audit' ), 'update-core.php' ) );

		if ( ! is_object( $transient ) || empty( $transient->updates ) || ! is_array( $transient->updates ) ) {
			return $this->result(
				'info',
				sprintf(
					/* translators: %s: version */
					__( 'WordPress %s. WordPress has not checked for updates recently, so we cannot tell whether a newer version exists.', 'iworksie-security-audit' ),
					$current
				),
				$why,
				__( 'Open Dashboard > Updates and click "Check again".', 'iworksie-security-audit' ),
				array( 'version' => $current ),
				$actions
			);
		}

		$latest = self::latest_offer( $transient->updates );
		if ( '' !== $latest && version_compare( $current, $latest, '<' ) ) {
			return $this->result(
				self::same_branch( $current, $latest ) ? 'critical' : 'recommended',
				sprintf(
					/* translators: 1: installed version, 2: available version */
					__( 'WordPress %1$s is installed; %2$s is available.', 'iworksie-security-audit' ),
					$current,
					$latest
				),
				$why,
				__( 'Take a backup, then update from Dashboard > Updates. Minor updates (the third number) are security fixes and rarely break anything.', 'iworksie-security-audit' ),
				array(
					'version' => $current,
					'latest'  => $latest,
				),
				$actions
			);
		}
		return $this->result(
			'good',
			sprintf(
				/* translators: %s: version */
				__( 'WordPress %s is the latest version.', 'iworksie-security-audit' ),
				$current
			),
			$why,
			$this->no_action(),
			array( 'version' => $current )
		);
	}

	/**
	 * Whether two versions share major.minor (e.g. 6.8.1 and 6.8.3: a security release is waiting). Pure function.
	 *
	 * @param string $a Version.
	 * @param string $b Version.
	 * @return bool
	 */
	public static function same_branch( $a, $b ) {
		$pa = explode( '.', (string) $a );
		$pb = explode( '.', (string) $b );
		return ( isset( $pa[1] ) ? $pa[0] . '.' . $pa[1] : $pa[0] ) === ( isset( $pb[1] ) ? $pb[0] . '.' . $pb[1] : $pb[0] );
	}

	/**
	 * Highest "upgrade" version offered in update_core data. Pure function.
	 *
	 * @param array<int,mixed> $updates update_core->updates.
	 * @return string
	 */
	public static function latest_offer( array $updates ) {
		$best = '';
		foreach ( $updates as $offer ) {
			$offer = (array) $offer;
			if ( ! isset( $offer['response'], $offer['current'] ) || 'upgrade' !== $offer['response'] ) {
				continue;
			}
			if ( '' === $best || version_compare( (string) $offer['current'], $best, '>' ) ) {
				$best = (string) $offer['current'];
			}
		}
		return $best;
	}
}
