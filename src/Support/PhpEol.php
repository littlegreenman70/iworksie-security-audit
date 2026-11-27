<?php
/**
 * PHP version / EOL classification.
 *
 * Update this table each year when PHP.net publishes new support dates.
 *
 * @package IWorksIE\SecurityAudit
 */

namespace IWorksIE\SecurityAudit\Support;

/**
 * Classify the running PHP version against known support windows.
 */
final class PhpEol {

	/**
	 * Known branch end dates (Y-m-d). Update yearly.
	 * Active support ends first; security support ends later.
	 *
	 * @return array<string,array{active:string,security:string}>
	 */
	public static function branches() {
		return array(
			'7.4' => array(
				'active'   => '2021-11-28',
				'security' => '2022-11-28',
			),
			'8.0' => array(
				'active'   => '2022-11-26',
				'security' => '2023-11-26',
			),
			'8.1' => array(
				'active'   => '2023-11-25',
				'security' => '2025-12-31',
			),
			'8.2' => array(
				'active'   => '2024-12-31',
				'security' => '2026-12-31',
			),
			'8.3' => array(
				'active'   => '2025-12-31',
				'security' => '2027-12-31',
			),
			'8.4' => array(
				'active'   => '2026-12-31',
				'security' => '2028-12-31',
			),
			'8.5' => array(
				'active'   => '2027-12-31',
				'security' => '2029-12-31',
			),
		);
	}

	/**
	 * Classify a PHP version string.
	 *
	 * @param string      $version PHP version.
	 * @param string|null $today   Y-m-d for tests.
	 * @return string critical|recommended|good
	 */
	public static function classify( $version, $today = null ) {
		$today  = null === $today ? gmdate( 'Y-m-d' ) : $today;
		$branch = self::branch_key( $version );
		$min_ok = '7.4';
		if ( version_compare( $branch, $min_ok, '<' ) ) {
			return 'critical';
		}
		$branches = self::branches();
		if ( ! isset( $branches[ $branch ] ) ) {
			// Unknown newer branch: treat as good (actively supported until table updates).
			if ( version_compare( $branch, '8.5', '>' ) ) {
				return 'good';
			}
			return 'critical';
		}
		$active   = $branches[ $branch ]['active'];
		$security = $branches[ $branch ]['security'];
		if ( $today > $security ) {
			return 'critical';
		}
		if ( $today > $active ) {
			return 'recommended';
		}
		return 'good';
	}

	/**
	 * Major.minor branch key.
	 *
	 * @param string $version Full version.
	 * @return string
	 */
	public static function branch_key( $version ) {
		$parts = explode( '.', (string) $version );
		$major = isset( $parts[0] ) ? (int) $parts[0] : 0;
		$minor = isset( $parts[1] ) ? (int) $parts[1] : 0;
		return $major . '.' . $minor;
	}
}
