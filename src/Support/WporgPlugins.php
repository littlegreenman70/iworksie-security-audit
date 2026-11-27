<?php
/**
 * Look up installed plugins on WordPress.org (closed or abandoned?).
 *
 * @package IWorksIE\SecurityAudit
 */

namespace IWorksIE\SecurityAudit\Support;

/**
 * Asks the public WordPress.org plugin directory API about each installed
 * plugin that comes from WordPress.org. Only the plugin slug is sent. Only runs
 * when an administrator runs the audit (or the weekly email they switched on).
 */
final class WporgPlugins {

	const CACHE_OPTION = 'iwiesa_wporg_cache';
	const CACHE_TTL    = 3 * DAY_IN_SECONDS;
	const TIME_BUDGET  = 15;
	const API          = 'https://api.wordpress.org/plugins/info/1.2/';

	/**
	 * Installed plugins that WordPress.org serves updates for: file => [slug, name].
	 *
	 * @return array<string,array{slug:string,name:string}>
	 */
	public static function installed() {
		if ( ! function_exists( 'get_plugins' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}
		$all       = get_plugins();
		$transient = get_site_transient( 'update_plugins' );
		$known     = array();
		if ( is_object( $transient ) ) {
			foreach ( array( 'response', 'no_update' ) as $bucket ) {
				if ( empty( $transient->$bucket ) || ! is_array( $transient->$bucket ) ) {
					continue;
				}
				foreach ( $transient->$bucket as $file => $item ) {
					$item = (array) $item;
					if ( ! empty( $item['slug'] ) && ( empty( $item['id'] ) || 0 === strpos( (string) $item['id'], 'w.org/' ) ) ) {
						$known[ (string) $file ] = (string) $item['slug'];
					}
				}
			}
		}

		$out = array();
		foreach ( $all as $file => $plugin ) {
			if ( ! isset( $known[ $file ] ) ) {
				continue;
			}
			$out[ $file ] = array(
				'slug' => $known[ $file ],
				'name' => isset( $plugin['Name'] ) ? (string) $plugin['Name'] : $known[ $file ],
			);
		}
		return $out;
	}

	/**
	 * Status for each slug, from cache or the API (within the time budget).
	 *
	 * @param array<int,string> $slugs Slugs.
	 * @return array<string,array{status:string,last_updated:int,reason:string}> Status: ok|closed|missing|unknown.
	 */
	public static function lookup( array $slugs ) {
		$cache = get_option( self::CACHE_OPTION, array() );
		if ( ! is_array( $cache ) ) {
			$cache = array();
		}
		$now     = time();
		$started = microtime( true );
		$out     = array();
		$dirty   = false;

		foreach ( array_unique( $slugs ) as $slug ) {
			$slug = sanitize_key( (string) $slug );
			if ( '' === $slug ) {
				continue;
			}
			if ( isset( $cache[ $slug ]['t'] ) && ( $now - (int) $cache[ $slug ]['t'] ) < self::CACHE_TTL ) {
				$out[ $slug ] = self::from_cache( $cache[ $slug ] );
				continue;
			}
			if ( ( microtime( true ) - $started ) > self::TIME_BUDGET ) {
				$out[ $slug ] = self::unknown();
				continue;
			}
			$info = self::fetch( $slug );
			if ( 'unknown' !== $info['status'] ) {
				$cache[ $slug ] = array(
					't' => $now,
					's' => $info['status'],
					'u' => $info['last_updated'],
					'r' => $info['reason'],
				);
				$dirty          = true;
			}
			$out[ $slug ] = $info;
		}

		if ( $dirty ) {
			update_option( self::CACHE_OPTION, $cache, false );
		}
		return $out;
	}

	/**
	 * One API request.
	 *
	 * @param string $slug Slug.
	 * @return array{status:string,last_updated:int,reason:string}
	 */
	private static function fetch( $slug ) {
		$url      = add_query_arg(
			array(
				'action'                        => 'plugin_information',
				'request[slug]'                 => $slug,
				'request[fields][sections]'     => '0',
				'request[fields][description]'  => '0',
				'request[fields][versions]'     => '0',
				'request[fields][screenshots]'  => '0',
				'request[fields][banners]'      => '0',
				'request[fields][icons]'        => '0',
				'request[fields][ratings]'      => '0',
				'request[fields][contributors]' => '0',
			),
			self::API
		);
		$response = wp_remote_get(
			$url,
			array(
				'timeout'    => 6,
				'user-agent' => 'WordPress/' . get_bloginfo( 'version' ) . '; iWorks.ie Security Audit',
			)
		);
		if ( is_wp_error( $response ) ) {
			return self::unknown();
		}
		return self::parse( (int) wp_remote_retrieve_response_code( $response ), (string) wp_remote_retrieve_body( $response ) );
	}

	/**
	 * Interpret an API response. Pure function.
	 *
	 * @param int    $code HTTP status.
	 * @param string $body JSON body.
	 * @return array{status:string,last_updated:int,reason:string}
	 */
	public static function parse( $code, $body ) {
		$json = json_decode( (string) $body, true );
		if ( ! is_array( $json ) ) {
			return self::unknown();
		}
		if ( ! empty( $json['closed'] ) || ( isset( $json['error'] ) && 'closed' === $json['error'] ) ) {
			return array(
				'status'       => 'closed',
				'last_updated' => 0,
				'reason'       => isset( $json['reason'] ) ? sanitize_key( (string) $json['reason'] ) : '',
			);
		}
		if ( isset( $json['error'] ) || 404 === (int) $code ) {
			return array(
				'status'       => 'missing',
				'last_updated' => 0,
				'reason'       => '',
			);
		}
		if ( 200 !== (int) $code ) {
			return self::unknown();
		}
		$updated = isset( $json['last_updated'] ) ? strtotime( (string) $json['last_updated'] ) : false;
		return array(
			'status'       => 'ok',
			'last_updated' => false !== $updated ? (int) $updated : 0,
			'reason'       => '',
		);
	}

	/**
	 * @param array<string,mixed> $row Cache row.
	 * @return array{status:string,last_updated:int,reason:string}
	 */
	private static function from_cache( array $row ) {
		return array(
			'status'       => isset( $row['s'] ) ? (string) $row['s'] : 'unknown',
			'last_updated' => isset( $row['u'] ) ? (int) $row['u'] : 0,
			'reason'       => isset( $row['r'] ) ? (string) $row['r'] : '',
		);
	}

	/**
	 * @return array{status:string,last_updated:int,reason:string}
	 */
	private static function unknown() {
		return array(
			'status'       => 'unknown',
			'last_updated' => 0,
			'reason'       => '',
		);
	}
}
