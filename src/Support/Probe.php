<?php
/**
 * Unauthenticated HTTP requests to this site, used to prove an exposure.
 *
 * @package IWorksIE\SecurityAudit
 */

namespace IWorksIE\SecurityAudit\Support;

/**
 * Makes small, read-only requests to the site's own URLs, the same way a
 * visitor (or attacker) would: no cookies, no redirects followed, and only the
 * first few kilobytes of the body are read.
 */
final class Probe {

	/**
	 * Bytes of body read per request.
	 */
	const BODY_LIMIT = 8192;

	/**
	 * Per-request timeout in seconds.
	 */
	const TIMEOUT = 6;

	/**
	 * Fetch a URL on this site.
	 *
	 * @param string              $url    Absolute URL.
	 * @param string              $method GET|POST|HEAD.
	 * @param array<string,mixed> $extra  Extra wp_remote_request args (e.g. body, headers).
	 * @return array{reachable:bool,code:int,body:string,headers:array<string,string>,error:string}
	 */
	public static function fetch( $url, $method = 'GET', array $extra = array() ) {
		$args = array_merge(
			array(
				'method'              => $method,
				'timeout'             => self::TIMEOUT,
				'redirection'         => 0,
				'limit_response_size' => self::BODY_LIMIT,
				'cookies'             => array(),
				'sslverify'           => (bool) apply_filters( 'https_local_ssl_verify', false ), // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- core filter, same as WordPress's own loopback requests.
				'user-agent'          => 'iWorks.ie Security Audit/' . ( defined( 'IWIESA_VERSION' ) ? IWIESA_VERSION : '1' ) . '; ' . home_url( '/' ),
				'headers'             => array(),
			),
			$extra
		);

		$response = wp_remote_request( $url, $args );
		if ( is_wp_error( $response ) ) {
			return array(
				'reachable' => false,
				'code'      => 0,
				'body'      => '',
				'headers'   => array(),
				'error'     => $response->get_error_message(),
			);
		}

		$headers = array();
		$raw     = wp_remote_retrieve_headers( $response );
		if ( is_object( $raw ) && method_exists( $raw, 'getAll' ) ) {
			$raw = $raw->getAll();
		}
		if ( is_array( $raw ) ) {
			foreach ( $raw as $name => $value ) {
				$headers[ strtolower( (string) $name ) ] = is_array( $value ) ? implode( ', ', array_map( 'strval', $value ) ) : (string) $value;
			}
		}

		$body = (string) wp_remote_retrieve_body( $response );
		if ( strlen( $body ) > self::BODY_LIMIT ) {
			$body = substr( $body, 0, self::BODY_LIMIT );
		}

		return array(
			'reachable' => true,
			'code'      => (int) wp_remote_retrieve_response_code( $response ),
			'body'      => $body,
			'headers'   => $headers,
			'error'     => '',
		);
	}

	/**
	 * Whether a response is a successful download (200 or partial 206).
	 *
	 * @param array{reachable:bool,code:int,body:string,headers:array<string,string>,error:string} $response Probe result.
	 * @return bool
	 */
	public static function is_ok( array $response ) {
		return $response['reachable'] && in_array( $response['code'], array( 200, 206 ), true );
	}

	/**
	 * Whether the body looks like an HTML page (soft 404s, themes, login walls).
	 *
	 * @param string $body Body prefix.
	 * @return bool
	 */
	public static function looks_like_html( $body ) {
		$start = strtolower( ltrim( substr( (string) $body, 0, 512 ) ) );
		return 0 === strpos( $start, '<!doctype html' )
			|| 0 === strpos( $start, '<html' )
			|| false !== strpos( $start, '<head' )
			|| false !== strpos( $start, '<body' );
	}
}
