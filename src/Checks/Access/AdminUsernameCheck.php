<?php
/**
 * Administrator accounts with guessable usernames.
 *
 * @package IWorksIE\SecurityAudit
 */

namespace IWorksIE\SecurityAudit\Checks\Access;

use IWorksIE\SecurityAudit\Checks\BaseCheck;
use IWorksIE\SecurityAudit\Vendor\IWorksIE\Core\Checks\Result;

/**
 * "admin", "administrator", the site name, etc.
 */
final class AdminUsernameCheck extends BaseCheck {

	const GUESSABLE = array( 'admin', 'administrator', 'root', 'test', 'demo', 'webmaster', 'wpadmin', 'user', 'manager', 'adm' );

	/** @return string */
	public function id() {
		return 'admin_username';
	}

	/** @return string */
	public function label() {
		return __( 'Administrator usernames', 'iworksie-security-audit' );
	}

	/** @return string */
	public function group() {
		return 'access';
	}

	/** @return Result */
	public function run() {
		$admins = get_users(
			array(
				'role'   => 'administrator',
				'fields' => array( 'user_login' ),
				'number' => 200,
			)
		);
		$logins = array();
		foreach ( $admins as $admin ) {
			$logins[] = (string) $admin->user_login;
		}
		$host  = (string) wp_parse_url( home_url(), PHP_URL_HOST );
		$risky = self::guessable( $logins, $host );
		$count = count( $logins );

		$why     = __( 'Bots try thousands of passwords against usernames like "admin" every day. A guessable username means they only have to find the password.', 'iworksie-security-audit' );
		$actions = array( $this->action( __( 'View administrators', 'iworksie-security-audit' ), 'users.php?role=administrator' ) );
		$data    = array( 'administrators' => $count );

		if ( ! empty( $risky ) ) {
			$data['matches'] = array();
			foreach ( $risky as $login ) {
				$data['matches'][] = array(
					'relative' => $login,
					'kind'     => __( 'Administrator', 'iworksie-security-audit' ),
				);
			}
			return $this->result(
				'recommended',
				sprintf(
					/* translators: %d: number of accounts */
					_n( '%d administrator has a username that is easy to guess.', '%d administrators have usernames that are easy to guess.', count( $risky ), 'iworksie-security-audit' ),
					count( $risky )
				),
				$why,
				__( 'Create a new administrator with a less obvious username and a strong password, log in as it, then delete the old account and choose "Attribute all content to" the new one. Usernames cannot be changed directly.', 'iworksie-security-audit' ),
				$data,
				$actions
			);
		}

		$text = sprintf(
			/* translators: %d: number of administrators */
			_n( 'No guessable administrator usernames. This site has %d administrator.', 'No guessable administrator usernames. This site has %d administrators.', $count, 'iworksie-security-audit' ),
			$count
		);
		if ( $count > 5 ) {
			return $this->result(
				'info',
				$text,
				$why,
				__( 'Every administrator is a way in. Check that each one still needs full access, and lower the others to Editor.', 'iworksie-security-audit' ),
				$data,
				$actions
			);
		}
		return $this->result( 'good', $text, $why, $this->no_action(), $data );
	}

	/**
	 * Logins that are easy to guess. Pure function.
	 *
	 * @param array<int,string> $logins Administrator logins.
	 * @param string            $host   Site host name.
	 * @return array<int,string>
	 */
	public static function guessable( array $logins, $host = '' ) {
		$host_words = array();
		$host       = strtolower( preg_replace( '/^www\./', '', (string) $host ) );
		if ( '' !== $host ) {
			$host_words[] = $host;
			$parts        = explode( '.', $host );
			if ( '' !== $parts[0] ) {
				$host_words[] = $parts[0];
			}
		}
		$out = array();
		foreach ( $logins as $login ) {
			$lower = strtolower( (string) $login );
			if ( in_array( $lower, self::GUESSABLE, true ) || in_array( $lower, $host_words, true ) ) {
				$out[] = (string) $login;
			}
		}
		return $out;
	}
}
