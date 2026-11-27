<?php
/**
 * Usernames revealed to logged-out visitors.
 *
 * @package IWorksIE\SecurityAudit
 */

namespace IWorksIE\SecurityAudit\Checks\Access;

use IWorksIE\SecurityAudit\Checks\BaseCheck;
use IWorksIE\SecurityAudit\Support\Probe;
use IWorksIE\SecurityAudit\Vendor\IWorksIE\Core\Checks\Result;

/**
 * REST users endpoint and ?author=N redirects.
 */
final class UserEnumerationCheck extends BaseCheck {

	/** @return string */
	public function id() {
		return 'user_enumeration';
	}

	/** @return string */
	public function label() {
		return __( 'Usernames visible to visitors', 'iworksie-security-audit' );
	}

	/** @return string */
	public function group() {
		return 'access';
	}

	/** @return Result */
	public function run() {
		$why = __( 'Bots collect usernames first, then try passwords against them. WordPress shows the login name of anyone who has published a post unless something hides it.', 'iworksie-security-audit' );

		$found   = array();
		$errors  = array();
		$checked = 0;

		$rest = Probe::fetch( add_query_arg( 'per_page', '5', rest_url( 'wp/v2/users' ) ) );
		if ( $rest['reachable'] ) {
			++$checked;
			foreach ( self::slugs_from_rest( $rest['code'], $rest['body'] ) as $slug ) {
				$found[ $slug ] = __( 'REST API', 'iworksie-security-audit' );
			}
		} else {
			$errors[] = $rest['error'];
		}

		$author = Probe::fetch( add_query_arg( 'author', '1', home_url( '/' ) ) );
		if ( $author['reachable'] ) {
			++$checked;
			$location = isset( $author['headers']['location'] ) ? $author['headers']['location'] : '';
			$slug     = self::slug_from_author_redirect( $author['code'], $location );
			if ( '' !== $slug && ! isset( $found[ $slug ] ) ) {
				$found[ $slug ] = __( 'Author archive link', 'iworksie-security-audit' );
			}
		} else {
			$errors[] = $author['error'];
		}

		if ( 0 === $checked ) {
			return $this->result(
				'info',
				sprintf(
					/* translators: %s: error message */
					__( 'Could not test: the site could not request its own pages (%s).', 'iworksie-security-audit' ),
					implode( '; ', array_unique( $errors ) )
				),
				$why,
				__( 'In a private browser window, open /wp-json/wp/v2/users on your site. If you see usernames ("slug"), follow the advice below.', 'iworksie-security-audit' )
			);
		}

		if ( ! empty( $found ) ) {
			$matches = array();
			foreach ( $found as $slug => $where ) {
				$matches[] = array(
					'relative' => (string) $slug,
					'kind'     => $where,
				);
			}
			return $this->result(
				'recommended',
				__( 'Logged-out visitors can see usernames on this site.', 'iworksie-security-audit' ),
				$why,
				__( 'This is not a hole on its own, but it makes password guessing easier. Use strong passwords and two-factor login (see "Login protection"), and make sure each user\'s "Display name publicly as" is not their username. Many security plugins can also hide the users list from logged-out visitors.', 'iworksie-security-audit' ),
				array( 'matches' => $matches )
			);
		}
		return $this->result( 'good', __( 'Usernames are not shown to logged-out visitors.', 'iworksie-security-audit' ), $why, $this->no_action() );
	}

	/**
	 * Usernames (slugs) in a /wp/v2/users response. Pure function.
	 *
	 * @param int    $code HTTP status.
	 * @param string $body Body prefix.
	 * @return array<int,string>
	 */
	public static function slugs_from_rest( $code, $body ) {
		if ( 200 !== (int) $code ) {
			return array();
		}
		$out  = array();
		$json = json_decode( (string) $body, true );
		if ( is_array( $json ) ) {
			foreach ( $json as $user ) {
				if ( is_array( $user ) && ! empty( $user['slug'] ) && is_string( $user['slug'] ) ) {
					$out[] = $user['slug'];
				}
			}
			return $out;
		}
		// Body may be cut off at the read limit; fall back to a pattern match.
		if ( preg_match_all( '/"slug"\s*:\s*"([^"\\\\]{1,60})"/', (string) $body, $m ) ) {
			$out = array_values( array_unique( $m[1] ) );
		}
		return $out;
	}

	/**
	 * Username revealed by a ?author=1 redirect. Pure function.
	 *
	 * @param int    $code     HTTP status.
	 * @param string $location Location header.
	 * @return string
	 */
	public static function slug_from_author_redirect( $code, $location ) {
		if ( (int) $code < 300 || (int) $code > 399 ) {
			return '';
		}
		if ( preg_match( '#/author/([^/?\#]+)#', (string) $location, $m ) ) {
			return rawurldecode( $m[1] );
		}
		return '';
	}
}
