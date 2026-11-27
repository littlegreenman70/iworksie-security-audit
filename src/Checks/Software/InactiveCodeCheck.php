<?php
/**
 * Inactive plugins and themes still on the server.
 *
 * @package IWorksIE\SecurityAudit
 */

namespace IWorksIE\SecurityAudit\Checks\Software;

use IWorksIE\SecurityAudit\Checks\BaseCheck;
use IWorksIE\SecurityAudit\Vendor\IWorksIE\Core\Checks\Result;

/**
 * Deactivated code can still be attacked directly.
 */
final class InactiveCodeCheck extends BaseCheck {

	/** @return string */
	public function id() {
		return 'inactive_code';
	}

	/** @return string */
	public function label() {
		return __( 'Inactive plugins and themes', 'iworksie-security-audit' );
	}

	/** @return string */
	public function group() {
		return 'software';
	}

	/** @return Result */
	public function run() {
		if ( ! function_exists( 'get_plugins' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}
		$why = __( 'Deactivated plugins and themes are still on the server, and their files can often be reached directly. They also stop getting attention, so they fall behind on updates.', 'iworksie-security-audit' );

		$matches = array();
		foreach ( get_plugins() as $file => $plugin ) {
			if ( is_plugin_active( $file ) || ( is_multisite() && is_plugin_active_for_network( $file ) ) ) {
				continue;
			}
			$matches[] = array(
				'relative' => (string) $plugin['Name'],
				'kind'     => __( 'Plugin', 'iworksie-security-audit' ),
			);
		}

		// Keep the active theme, its parent, and one spare default theme for emergencies.
		$keep = array( get_stylesheet(), get_template() );
		if ( defined( 'WP_DEFAULT_THEME' ) ) {
			$keep[] = WP_DEFAULT_THEME;
		}
		$inactive_themes = array();
		foreach ( wp_get_themes() as $slug => $theme ) {
			if ( ! in_array( $slug, $keep, true ) ) {
				$inactive_themes[ $slug ] = $theme;
			}
		}
		// Allow one inactive default "Twenty" theme as a fallback.
		foreach ( array_keys( $inactive_themes ) as $slug ) {
			if ( 0 === strpos( (string) $slug, 'twenty' ) ) {
				unset( $inactive_themes[ $slug ] );
				break;
			}
		}
		foreach ( $inactive_themes as $theme ) {
			$matches[] = array(
				'relative' => (string) $theme->get( 'Name' ),
				'kind'     => __( 'Theme', 'iworksie-security-audit' ),
			);
		}

		if ( empty( $matches ) ) {
			return $this->result( 'good', __( 'No unused plugins or themes are lying around.', 'iworksie-security-audit' ), $why, $this->no_action() );
		}
		return $this->result(
			'recommended',
			sprintf(
				/* translators: %d: number of items */
				_n( '%d inactive plugin or theme is still installed.', '%d inactive plugins and themes are still installed.', count( $matches ), 'iworksie-security-audit' ),
				count( $matches )
			),
			$why,
			__( 'Delete anything you are not going to use again (Plugins > Inactive, and Appearance > Themes). Keeping one default theme such as Twenty Twenty-Five as a fallback is fine.', 'iworksie-security-audit' ),
			array( 'matches' => $matches ),
			array( $this->action( __( 'Inactive plugins', 'iworksie-security-audit' ), 'plugins.php?plugin_status=inactive' ) )
		);
	}
}
