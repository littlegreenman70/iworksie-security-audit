<?php
/**
 * Byte and memory string helpers.
 *
 * @package IWorksIE\SecurityAudit
 */

namespace IWorksIE\SecurityAudit\Support;

/**
 * Parse and format byte sizes.
 */
final class Bytes {

	/**
	 * Parse a PHP memory string (128M, 1G, -1) into bytes.
	 *
	 * @param string|int $value Raw value.
	 * @return int Bytes, or -1 for unlimited.
	 */
	public static function parse( $value ) {
		if ( is_int( $value ) ) {
			return $value;
		}
		$value = trim( (string) $value );
		if ( '' === $value || '-1' === $value ) {
			return -1;
		}
		if ( ! preg_match( '/^(\d+)([KMG]?)$/i', $value, $m ) ) {
			$as_int = (int) $value;
			return $as_int;
		}
		$num  = (int) $m[1];
		$unit = strtoupper( $m[2] );
		switch ( $unit ) {
			case 'G':
				return $num * 1024 * 1024 * 1024;
			case 'M':
				return $num * 1024 * 1024;
			case 'K':
				return $num * 1024;
			default:
				return $num;
		}
	}

	/**
	 * Human-readable size.
	 *
	 * @param int $bytes Bytes.
	 * @return string
	 */
	public static function format( $bytes ) {
		$bytes = (int) $bytes;
		if ( $bytes < 0 ) {
			return __( 'unlimited', 'iworksie-security-audit' );
		}
		$units    = array( 'B', 'KB', 'MB', 'GB', 'TB' );
		$unit_max = count( $units ) - 1;
		$i        = 0;
		$n        = (float) $bytes;
		while ( $n >= 1024 && $i < $unit_max ) {
			$n /= 1024;
			++$i;
		}
		$precision = ( $i >= 2 ) ? 1 : 0;
		return number_format_i18n( $n, $precision ) . ' ' . $units[ $i ];
	}
}
