<?php
/**
 * Persist check results between admin loads.
 *
 * @package IWorksIE\SecurityAudit
 */

namespace IWorksIE\SecurityAudit\Support;

/**
 * Non-autoloaded option cache for check results.
 *
 * Results are recorded server-side only (never from a browser-posted payload).
 */
final class ResultsCache {

	const OPTION = 'iwiesa_results';

	/**
	 * Replace the full results set (CLI / internal).
	 *
	 * @param array<string,array<string,mixed>> $results Results keyed by check id.
	 * @return void
	 */
	public static function save( array $results ) {
		$clean = array();
		foreach ( $results as $id => $row ) {
			if ( ! is_array( $row ) ) {
				continue;
			}
			$clean[ sanitize_key( (string) $id ) ] = self::sanitize_result( $row );
		}
		update_option(
			self::OPTION,
			array(
				'time'    => time(),
				'results' => $clean,
			),
			false
		);
	}

	/**
	 * Merge one server-run check result into the cache.
	 *
	 * @param string              $id     Check id.
	 * @param array<string,mixed> $result Result::to_array() payload.
	 * @return void
	 */
	public static function save_one( $id, array $result ) {
		$id   = sanitize_key( (string) $id );
		$data = get_option( self::OPTION, null );
		if ( ! is_array( $data ) ) {
			$data = array(
				'time'    => 0,
				'results' => array(),
			);
		}
		if ( empty( $data['results'] ) || ! is_array( $data['results'] ) ) {
			$data['results'] = array();
		}
		$data['results'][ $id ] = self::sanitize_result( $result );
		$data['time']           = time();
		update_option( self::OPTION, $data, false );
	}

	/**
	 * Stamp "last checked" without changing stored results.
	 *
	 * @return void
	 */
	public static function touch() {
		$data = get_option( self::OPTION, null );
		if ( ! is_array( $data ) ) {
			$data = array(
				'time'    => time(),
				'results' => array(),
			);
		} else {
			$data['time'] = time();
			if ( empty( $data['results'] ) || ! is_array( $data['results'] ) ) {
				$data['results'] = array();
			}
		}
		update_option( self::OPTION, $data, false );
	}

	/**
	 * Sanitize a Result::to_array() row before storage.
	 *
	 * Action URLs must be admin_url() links; data is kept as scalar/array
	 * structure but string leaves are sanitized.
	 *
	 * @param array<string,mixed> $row Result array.
	 * @return array<string,mixed>
	 */
	public static function sanitize_result( array $row ) {
		$status  = isset( $row['status'] ) ? sanitize_key( (string) $row['status'] ) : 'info';
		$allowed = array( 'good', 'recommended', 'critical', 'info' );
		if ( ! in_array( $status, $allowed, true ) ) {
			$status = 'info';
		}
		return array(
			'status'      => $status,
			'label'       => isset( $row['label'] ) ? sanitize_text_field( (string) $row['label'] ) : '',
			'description' => isset( $row['description'] ) ? sanitize_textarea_field( (string) $row['description'] ) : '',
			'why'         => isset( $row['why'] ) ? sanitize_textarea_field( (string) $row['why'] ) : '',
			'fix'         => isset( $row['fix'] ) ? sanitize_textarea_field( (string) $row['fix'] ) : '',
			'data'        => isset( $row['data'] ) && is_array( $row['data'] ) ? self::sanitize_data( $row['data'] ) : array(),
			'actions'     => isset( $row['actions'] ) && is_array( $row['actions'] ) ? self::sanitize_actions( $row['actions'] ) : array(),
		);
	}

	/**
	 * @param array<string,mixed> $data Extra data.
	 * @return array<string,mixed>
	 */
	private static function sanitize_data( array $data ) {
		$out = array();
		foreach ( $data as $key => $value ) {
			$safe_key = sanitize_key( (string) $key );
			if ( is_array( $value ) ) {
				$out[ $safe_key ] = self::sanitize_data( $value );
			} elseif ( is_bool( $value ) || is_int( $value ) || is_float( $value ) ) {
				$out[ $safe_key ] = $value;
			} else {
				$out[ $safe_key ] = sanitize_text_field( (string) $value );
			}
		}
		return $out;
	}

	/**
	 * Keep only admin_url() action links.
	 *
	 * @param array<int,mixed> $actions Actions.
	 * @return array<int,array{label:string,url:string}>
	 */
	private static function sanitize_actions( array $actions ) {
		$admin = function_exists( 'admin_url' ) ? (string) admin_url() : '';
		$out   = array();
		foreach ( $actions as $action ) {
			if ( ! is_array( $action ) ) {
				continue;
			}
			$label = isset( $action['label'] ) ? sanitize_text_field( (string) $action['label'] ) : '';
			$url   = isset( $action['url'] ) ? (string) $action['url'] : '';
			if ( '' === $label || '' === $url ) {
				continue;
			}
			$url = esc_url_raw( $url );
			if ( '' === $url || '' === $admin || 0 !== strpos( $url, $admin ) ) {
				continue;
			}
			$out[] = array(
				'label' => $label,
				'url'   => $url,
			);
		}
		return $out;
	}

	/**
	 * Load cached payload.
	 *
	 * @return array{time:int,results:array<string,array<string,mixed>>}|null
	 */
	public static function load() {
		$data = get_option( self::OPTION, null );
		if ( ! is_array( $data ) || empty( $data['results'] ) || ! is_array( $data['results'] ) ) {
			return null;
		}
		return array(
			'time'    => isset( $data['time'] ) ? (int) $data['time'] : 0,
			'results' => $data['results'],
		);
	}

	/**
	 * Human "Last checked …" string.
	 *
	 * @return string
	 */
	public static function last_checked_label() {
		$data = self::load();
		if ( null === $data || empty( $data['time'] ) ) {
			return __( 'Not audited yet.', 'iworksie-security-audit' );
		}
		return sprintf(
			/* translators: %s: human time difference */
			__( 'Last audited %s ago', 'iworksie-security-audit' ),
			human_time_diff( (int) $data['time'], time() )
		);
	}
}
