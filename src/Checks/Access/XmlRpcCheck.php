<?php
/**
 * XML-RPC password guessing endpoint.
 *
 * @package IWorksIE\SecurityAudit
 */

namespace IWorksIE\SecurityAudit\Checks\Access;

use IWorksIE\SecurityAudit\Checks\BaseCheck;
use IWorksIE\SecurityAudit\Support\Probe;
use IWorksIE\SecurityAudit\Vendor\IWorksIE\Core\Checks\Result;

/**
 * xmlrpc_enabled filter + a harmless system.listMethods request.
 */
final class XmlRpcCheck extends BaseCheck {

	/** @return string */
	public function id() {
		return 'xmlrpc';
	}

	/** @return string */
	public function label() {
		return __( 'XML-RPC', 'iworksie-security-audit' );
	}

	/** @return string */
	public function group() {
		return 'access';
	}

	/** @return Result */
	public function run() {
		$why = __( 'xmlrpc.php is an old remote-publishing interface. Bots use it to try hundreds of passwords in a single request, which gets past many login limiters. Most sites no longer need it (the Jetpack plugin and some mobile apps are the main exceptions).', 'iworksie-security-audit' );
		$fix = __( 'If you do not use Jetpack or a desktop/mobile publishing app, block xmlrpc.php. Most security plugins have a "Disable XML-RPC" switch, or your host can block it at the server.', 'iworksie-security-audit' );

		if ( ! apply_filters( 'xmlrpc_enabled', true ) ) { // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- reading core's own setting.
			return $this->result( 'good', __( 'XML-RPC logins are switched off by a plugin or theme.', 'iworksie-security-audit' ), $why, $this->no_action() );
		}

		$body     = '<?xml version="1.0"?><methodCall><methodName>system.listMethods</methodName><params></params></methodCall>';
		$response = Probe::fetch(
			site_url( 'xmlrpc.php' ),
			'POST',
			array(
				'body'    => $body,
				'headers' => array( 'Content-Type' => 'text/xml' ),
			)
		);

		if ( ! $response['reachable'] ) {
			return $this->result(
				'info',
				sprintf(
					/* translators: %s: error message */
					__( 'XML-RPC is switched on in WordPress, but we could not test whether the server blocks it (%s).', 'iworksie-security-audit' ),
					$response['error']
				),
				$why,
				$fix
			);
		}
		if ( 200 === $response['code'] && false !== strpos( $response['body'], 'methodResponse' ) ) {
			$multicall = false !== strpos( $response['body'], 'system.multicall' );
			return $this->result(
				'recommended',
				$multicall
					? __( 'xmlrpc.php is open and accepts many login attempts in one request (system.multicall).', 'iworksie-security-audit' )
					: __( 'xmlrpc.php is open to the public.', 'iworksie-security-audit' ),
				$why,
				$fix,
				array( 'multicall' => $multicall )
			);
		}
		return $this->result( 'good', __( 'xmlrpc.php is blocked at the server.', 'iworksie-security-audit' ), $why, $this->no_action(), array( 'http_code' => $response['code'] ) );
	}
}
