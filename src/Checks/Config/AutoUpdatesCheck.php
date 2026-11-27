<?php
/**
 * Automatic security updates for WordPress core.
 *
 * @package IWorksIE\SecurityAudit
 */

namespace IWorksIE\SecurityAudit\Checks\Config;

use IWorksIE\SecurityAudit\Checks\BaseCheck;
use IWorksIE\SecurityAudit\Vendor\IWorksIE\Core\Checks\Result;

/**
 * AUTOMATIC_UPDATER_DISABLED / WP_AUTO_UPDATE_CORE.
 */
final class AutoUpdatesCheck extends BaseCheck {

	/** @return string */
	public function id() {
		return 'core_auto_updates';
	}

	/** @return string */
	public function label() {
		return __( 'Automatic security releases', 'iworksie-security-audit' );
	}

	/** @return string */
	public function group() {
		return 'config';
	}

	/** @return Result */
	public function run() {
		$why = __( 'WordPress ships urgent security fixes as small automatic updates (for example 6.8.1 to 6.8.2). With them blocked, a known hole stays open until someone updates by hand.', 'iworksie-security-audit' );
		$fix = __( 'Remove AUTOMATIC_UPDATER_DISABLED from wp-config.php, and set WP_AUTO_UPDATE_CORE to \'minor\' or true rather than false. If your host manages updates for you, you can ignore this.', 'iworksie-security-audit' );

		$all_off   = ( defined( 'AUTOMATIC_UPDATER_DISABLED' ) && AUTOMATIC_UPDATER_DISABLED ) || ( defined( 'DISALLOW_FILE_MODS' ) && DISALLOW_FILE_MODS )
			|| (bool) apply_filters( 'automatic_updater_disabled', false ); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- reading core's own setting.
		$core_off  = defined( 'WP_AUTO_UPDATE_CORE' ) && false === WP_AUTO_UPDATE_CORE;
		$filter_on = (bool) apply_filters( 'allow_minor_auto_core_updates', true ); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- reading core's own setting.

		if ( $all_off || $core_off || ! $filter_on ) {
			return $this->result(
				'recommended',
				__( 'Automatic security releases for WordPress are switched off.', 'iworksie-security-audit' ),
				$why,
				$fix
			);
		}
		return $this->result( 'good', __( 'WordPress will install security releases automatically.', 'iworksie-security-audit' ), $why, $this->no_action() );
	}
}
