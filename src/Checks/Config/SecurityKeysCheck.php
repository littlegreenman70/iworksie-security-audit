<?php
/**
 * Authentication keys and salts.
 *
 * @package IWorksIE\SecurityAudit
 */

namespace IWorksIE\SecurityAudit\Checks\Config;

use IWorksIE\SecurityAudit\Checks\BaseCheck;
use IWorksIE\SecurityAudit\Vendor\IWorksIE\Core\Checks\Result;

/**
 * Keys present, unique, long, not the sample phrase.
 */
final class SecurityKeysCheck extends BaseCheck {

	const KEYS = array( 'AUTH_KEY', 'SECURE_AUTH_KEY', 'LOGGED_IN_KEY', 'NONCE_KEY', 'AUTH_SALT', 'SECURE_AUTH_SALT', 'LOGGED_IN_SALT', 'NONCE_SALT' );

	/** @return string */
	public function id() {
		return 'security_keys';
	}

	/** @return string */
	public function label() {
		return __( 'Security keys and salts', 'iworksie-security-audit' );
	}

	/** @return string */
	public function group() {
		return 'config';
	}

	/** @return Result */
	public function run() {
		$values = array();
		foreach ( self::KEYS as $name ) {
			$values[ $name ] = defined( $name ) ? (string) constant( $name ) : null;
		}
		$problems = self::problems( $values );

		$why = __( 'These random values sign the login cookies. If they are missing, weak or the sample text, someone could forge a cookie and log in without a password.', 'iworksie-security-audit' );
		$fix = __( 'Get a fresh set from https://api.wordpress.org/secret-key/1.1/salt/ and replace the eight define() lines in wp-config.php. Everyone will be logged out once, which is expected.', 'iworksie-security-audit' );

		if ( ! empty( $problems['default'] ) || ! empty( $problems['weak'] ) ) {
			$names = array_merge( $problems['default'], $problems['weak'] );
			return $this->result(
				'critical',
				sprintf(
					/* translators: %s: list of constant names */
					__( 'These keys still use the sample text or are too short: %s.', 'iworksie-security-audit' ),
					implode( ', ', $names )
				),
				$why,
				$fix,
				array( 'keys' => $names )
			);
		}
		if ( ! empty( $problems['duplicate'] ) || ! empty( $problems['missing'] ) ) {
			$names = array_merge( $problems['duplicate'], $problems['missing'] );
			return $this->result(
				'recommended',
				sprintf(
					/* translators: %s: list of constant names */
					__( 'These keys are missing from wp-config.php or share the same value: %s. WordPress falls back to keys stored in the database, which is weaker.', 'iworksie-security-audit' ),
					implode( ', ', $names )
				),
				$why,
				$fix,
				array( 'keys' => $names )
			);
		}
		return $this->result( 'good', __( 'All eight keys and salts are set, long and unique.', 'iworksie-security-audit' ), $why, $this->no_action() );
	}

	/**
	 * Classify key values. Pure function (values never leave this method).
	 *
	 * @param array<string,string|null> $values Constant name => value (null when undefined).
	 * @return array{missing:array<int,string>,default:array<int,string>,weak:array<int,string>,duplicate:array<int,string>}
	 */
	public static function problems( array $values ) {
		$out    = array(
			'missing'   => array(),
			'default'   => array(),
			'weak'      => array(),
			'duplicate' => array(),
		);
		$counts = array();
		foreach ( $values as $value ) {
			if ( null !== $value && '' !== $value ) {
				$counts[ $value ] = isset( $counts[ $value ] ) ? $counts[ $value ] + 1 : 1;
			}
		}
		foreach ( $values as $name => $value ) {
			if ( null === $value || '' === $value ) {
				$out['missing'][] = $name;
			} elseif ( false !== stripos( $value, 'put your unique phrase here' ) ) {
				$out['default'][] = $name;
			} elseif ( strlen( $value ) < 32 ) {
				$out['weak'][] = $name;
			} elseif ( $counts[ $value ] > 1 ) {
				$out['duplicate'][] = $name;
			}
		}
		return $out;
	}
}
