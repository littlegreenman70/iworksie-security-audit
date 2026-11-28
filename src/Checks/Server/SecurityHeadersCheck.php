<?php
/**
 * Browser security headers on the home page.
 *
 * @package IWorksIE\SecurityAudit
 */

namespace IWorksIE\SecurityAudit\Checks\Server;

use IWorksIE\SecurityAudit\Checks\BaseCheck;
use IWorksIE\SecurityAudit\Support\Probe;
use IWorksIE\SecurityAudit\Vendor\IWorksIE\Core\Checks\Result;

/**
 * HSTS, nosniff, framing, referrer policy; PHP version leaks.
 */
final class SecurityHeadersCheck extends BaseCheck {

	/** @return string */
	public function id() {
		return 'security_headers';
	}

	/** @return string */
	public function label() {
		return __( 'Security headers', 'iworksie-security-audit' );
	}

	/** @return string */
	public function group() {
		return 'server';
	}

	/** @return Result */
	public function run() {
		$why = __( 'Security headers are instructions your server sends to browsers: always use HTTPS, do not let other sites put this site in a frame (clickjacking), and so on. They are a cheap second line of defence.', 'iworksie-security-audit' );
		$fix = __( 'Ask your host or developer to add the missing headers at the server or CDN (Cloudflare can add most of them in a few clicks). Test the result at securityheaders.com.', 'iworksie-security-audit' );

		$response = Probe::fetch( home_url( '/' ), 'GET', array( 'redirection' => 3 ) );
		if ( ! $response['reachable'] ) {
			return $this->result(
				'info',
				sprintf(
					/* translators: %s: error message */
					__( 'Could not test: the site could not request its own home page (%s).', 'iworksie-security-audit' ),
					$response['error']
				),
				$why,
				$fix
			);
		}

		$https   = 'https' === wp_parse_url( home_url(), PHP_URL_SCHEME );
		$missing = self::missing( $response['headers'], $https );
		$leak    = self::version_leak( $response['headers'] );

		$matches = array();
		foreach ( $missing as $header => $purpose ) {
			$matches[] = array(
				'relative' => $header,
				'kind'     => $purpose,
			);
		}
		if ( '' !== $leak ) {
			$matches[] = array(
				'relative' => $leak,
				'kind'     => __( 'Reveals software version', 'iworksie-security-audit' ),
			);
		}

		if ( empty( $matches ) ) {
			return $this->result( 'good', __( 'The main security headers are in place.', 'iworksie-security-audit' ), $why, $this->no_action() );
		}
		return $this->result(
			'recommended',
			empty( $missing )
				? __( 'The security headers are in place, but the server announces its software version.', 'iworksie-security-audit' )
				: sprintf(
					/* translators: %d: number of headers */
					_n( '%d recommended security header is missing.', '%d recommended security headers are missing.', count( $missing ), 'iworksie-security-audit' ),
					count( $missing )
				),
			$why,
			$fix . ( '' !== $leak ? ' ' . __( 'To hide the version, set expose_php = Off in php.ini (or ask your host).', 'iworksie-security-audit' ) : '' ),
			array( 'matches' => $matches )
		);
	}

	/**
	 * Missing headers => what they do. Pure function.
	 *
	 * @param array<string,string> $headers Lower-case header map.
	 * @param bool                 $https   Whether the site uses HTTPS.
	 * @return array<string,string>
	 */
	public static function missing( array $headers, $https ) {
		$missing = array();
		if ( $https && empty( $headers['strict-transport-security'] ) ) {
			$missing['Strict-Transport-Security'] = __( 'Forces HTTPS on return visits', 'iworksie-security-audit' );
		}
		if ( empty( $headers['x-content-type-options'] ) || false === stripos( $headers['x-content-type-options'], 'nosniff' ) ) {
			$missing['X-Content-Type-Options'] = __( 'Stops browsers guessing file types', 'iworksie-security-audit' );
		}
		$csp_frames = ! empty( $headers['content-security-policy'] ) && false !== stripos( $headers['content-security-policy'], 'frame-ancestors' );
		if ( empty( $headers['x-frame-options'] ) && ! $csp_frames ) {
			$missing['X-Frame-Options'] = __( 'Blocks clickjacking in frames', 'iworksie-security-audit' );
		}
		if ( empty( $headers['referrer-policy'] ) ) {
			$missing['Referrer-Policy'] = __( 'Limits what other sites see about your links', 'iworksie-security-audit' );
		}
		return $missing;
	}

	/**
	 * "X-Powered-By: PHP/8.1.2"-style leak. Pure function.
	 *
	 * @param array<string,string> $headers Lower-case header map.
	 * @return string Header line or ''.
	 */
	public static function version_leak( array $headers ) {
		if ( ! empty( $headers['x-powered-by'] ) && preg_match( '/PHP\/\d/i', $headers['x-powered-by'] ) ) {
			return 'X-Powered-By: ' . $headers['x-powered-by'];
		}
		return '';
	}
}
