<?php
/**
 * Two-factor login / login attempt limits.
 *
 * @package IWorksIE\SecurityAudit
 */

namespace IWorksIE\SecurityAudit\Checks\Access;

use IWorksIE\SecurityAudit\Checks\BaseCheck;
use IWorksIE\SecurityAudit\Vendor\IWorksIE\Core\Checks\Result;

/**
 * Looks for well-known plugins that add 2FA or limit login attempts.
 */
final class LoginProtectionCheck extends BaseCheck {

	/**
	 * Plugin folder => name. Filterable via iwiesa_login_protection_plugins.
	 *
	 * @var array<string,string>
	 */
	const KNOWN = array(
		'two-factor'                          => 'Two Factor',
		'wp-2fa'                              => 'WP 2FA',
		'wordfence'                           => 'Wordfence',
		'wordfence-login-security'            => 'Wordfence Login Security',
		'better-wp-security'                  => 'Solid Security',
		'ithemes-security-pro'                => 'Solid Security Pro',
		'limit-login-attempts-reloaded'       => 'Limit Login Attempts Reloaded',
		'loginizer'                           => 'Loginizer',
		'all-in-one-wp-security-and-firewall' => 'All-In-One Security',
		'wp-cerber'                           => 'WP Cerber',
		'wp-simple-firewall'                  => 'Shield Security',
		'google-authenticator'                => 'Google Authenticator',
		'miniorange-2-factor-authentication'  => 'miniOrange 2FA',
		'two-factor-authentication'           => 'Two Factor Authentication',
		'login-lockdown'                      => 'Login Lockdown',
		'wps-limit-login'                     => 'WPS Limit Login',
		'really-simple-ssl'                   => 'Really Simple Security',
		'sucuri-scanner'                      => 'Sucuri Security',
		'jetpack-protect'                     => 'Jetpack Protect',
		'defender-security'                   => 'Defender Security',
		'cleantalk-spam-protect'              => 'CleanTalk',
		'secupress'                           => 'SecuPress',
		'aios-pro'                            => 'All-In-One Security Premium',
	);

	/** @return string */
	public function id() {
		return 'login_protection';
	}

	/** @return string */
	public function label() {
		return __( 'Login protection', 'iworksie-security-audit' );
	}

	/** @return string */
	public function group() {
		return 'access';
	}

	/** @return Result */
	public function run() {
		$known = (array) apply_filters( 'iwiesa_login_protection_plugins', self::KNOWN );
		$found = self::detect( $this->active_plugin_files(), $known );
		$why   = __( 'Stolen or guessed passwords are the most common way WordPress sites get taken over. Two-factor login (a code from your phone) or a limit on failed attempts stops almost all of it.', 'iworksie-security-audit' );

		if ( ! empty( $found ) ) {
			return $this->result(
				'good',
				sprintf(
					/* translators: %s: plugin names */
					__( 'Login protection found: %s. Make sure two-factor login is switched on for every administrator.', 'iworksie-security-audit' ),
					implode( ', ', $found )
				),
				$why,
				$this->no_action(),
				array( 'plugins' => $found )
			);
		}
		return $this->result(
			'recommended',
			__( 'No two-factor login or login-limit plugin was found. (Protection set up at your host or in a plugin we do not recognise will not show here.)', 'iworksie-security-audit' ),
			$why,
			__( 'Install a free two-factor plugin such as "Two Factor" (maintained by WordPress contributors) and turn it on for every administrator. If you only want a limit on failed logins, "Limit Login Attempts Reloaded" is a popular free choice.', 'iworksie-security-audit' ),
			array(),
			array( $this->action( __( 'Find a two-factor plugin', 'iworksie-security-audit' ), 'plugin-install.php?s=two-factor&tab=search&type=term' ) )
		);
	}

	/**
	 * Names of known protection plugins among active plugin files. Pure function.
	 *
	 * @param array<int,string>    $active Plugin files (folder/file.php).
	 * @param array<string,string> $known  Folder => name.
	 * @return array<int,string>
	 */
	public static function detect( array $active, array $known ) {
		$out = array();
		foreach ( $active as $file ) {
			$folder = strtolower( (string) strtok( (string) $file, '/' ) );
			if ( isset( $known[ $folder ] ) ) {
				$out[] = (string) $known[ $folder ];
			}
		}
		return array_values( array_unique( $out ) );
	}

	/**
	 * Active plugin files, including network-activated ones.
	 *
	 * @return array<int,string>
	 */
	private function active_plugin_files() {
		$active = (array) get_option( 'active_plugins', array() );
		if ( is_multisite() ) {
			$network = (array) get_site_option( 'active_sitewide_plugins', array() );
			$active  = array_merge( $active, array_keys( $network ) );
		}
		return array_values( array_map( 'strval', $active ) );
	}
}
