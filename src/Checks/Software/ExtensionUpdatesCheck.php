<?php
/**
 * Plugin and theme updates waiting.
 *
 * @package IWorksIE\SecurityAudit
 */

namespace IWorksIE\SecurityAudit\Checks\Software;

use IWorksIE\SecurityAudit\Checks\BaseCheck;
use IWorksIE\SecurityAudit\Vendor\IWorksIE\Core\Checks\Result;

/**
 * Reads update_plugins / update_themes site transients.
 */
final class ExtensionUpdatesCheck extends BaseCheck {

	/** @return string */
	public function id() {
		return 'extension_updates';
	}

	/** @return string */
	public function label() {
		return __( 'Plugin and theme updates', 'iworksie-security-audit' );
	}

	/** @return string */
	public function group() {
		return 'software';
	}

	/** @return Result */
	public function run() {
		$why     = __( 'Most hacked WordPress sites are broken into through a plugin with a known, already-fixed hole. Updates are how the fix reaches you.', 'iworksie-security-audit' );
		$actions = array( $this->action( __( 'Open Updates', 'iworksie-security-audit' ), 'update-core.php' ) );

		$plugins = get_site_transient( 'update_plugins' );
		$themes  = get_site_transient( 'update_themes' );
		if ( ! is_object( $plugins ) && ! is_object( $themes ) ) {
			return $this->result(
				'info',
				__( 'WordPress has not checked for plugin and theme updates recently.', 'iworksie-security-audit' ),
				$why,
				__( 'Open Dashboard > Updates and click "Check again".', 'iworksie-security-audit' ),
				array(),
				$actions
			);
		}

		$matches = array();
		if ( is_object( $plugins ) && ! empty( $plugins->response ) && is_array( $plugins->response ) ) {
			if ( ! function_exists( 'get_plugins' ) ) {
				require_once ABSPATH . 'wp-admin/includes/plugin.php';
			}
			$all = get_plugins();
			foreach ( $plugins->response as $file => $offer ) {
				$offer     = (array) $offer;
				$name      = isset( $all[ $file ]['Name'] ) ? (string) $all[ $file ]['Name'] : (string) $file;
				$installed = isset( $all[ $file ]['Version'] ) ? (string) $all[ $file ]['Version'] : '';
				$matches[] = array(
					'relative' => $name . ( '' !== $installed ? ' ' . $installed : '' ) . ( isset( $offer['new_version'] ) ? ' → ' . (string) $offer['new_version'] : '' ),
					'kind'     => __( 'Plugin', 'iworksie-security-audit' ),
				);
			}
		}
		if ( is_object( $themes ) && ! empty( $themes->response ) && is_array( $themes->response ) ) {
			foreach ( $themes->response as $stylesheet => $offer ) {
				$offer     = (array) $offer;
				$theme     = wp_get_theme( (string) $stylesheet );
				$name      = $theme->exists() ? (string) $theme->get( 'Name' ) . ' ' . (string) $theme->get( 'Version' ) : (string) $stylesheet;
				$matches[] = array(
					'relative' => $name . ( isset( $offer['new_version'] ) ? ' → ' . (string) $offer['new_version'] : '' ),
					'kind'     => __( 'Theme', 'iworksie-security-audit' ),
				);
			}
		}

		if ( empty( $matches ) ) {
			return $this->result( 'good', __( 'All plugins and themes are up to date.', 'iworksie-security-audit' ), $why, $this->no_action() );
		}
		return $this->result(
			count( $matches ) >= 5 ? 'critical' : 'recommended',
			sprintf(
				/* translators: %d: number of updates */
				_n( '%d plugin or theme update is waiting.', '%d plugin and theme updates are waiting.', count( $matches ), 'iworksie-security-audit' ),
				count( $matches )
			),
			$why,
			__( 'Take a backup, then update from Dashboard > Updates. Consider switching on auto-updates (Plugins screen, "Enable auto-updates") for plugins you trust.', 'iworksie-security-audit' ),
			array( 'matches' => $matches ),
			$actions
		);
	}
}
