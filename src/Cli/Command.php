<?php
/**
 * WP-CLI command: wp iworksie-security audit
 *
 * @package IWorksIE\SecurityAudit
 */

namespace IWorksIE\SecurityAudit\Cli;

use IWorksIE\SecurityAudit\Plugin;
use IWorksIE\SecurityAudit\Support\ResultsCache;

/**
 * Run the security audit from the command line.
 */
final class Command {

	/**
	 * Register when WP-CLI is present.
	 *
	 * @return void
	 */
	public static function register() {
		if ( ! defined( 'WP_CLI' ) || ! WP_CLI ) {
			return;
		}
		\WP_CLI::add_command( 'iworksie-security', self::class );
	}

	/**
	 * Run every security check.
	 *
	 * ## OPTIONS
	 *
	 * [--format=<format>]
	 * : table or json
	 * ---
	 * default: table
	 * options:
	 *   - table
	 *   - json
	 * ---
	 *
	 * @param array<int,string>    $args  Positional.
	 * @param array<string,string> $assoc Assoc.
	 * @return void
	 */
	public function audit( $args, $assoc ) {
		$core = Plugin::instance()->core();
		if ( null === $core ) {
			\WP_CLI::error( 'Plugin core is not booted.' );
			return;
		}
		$results = $core->checks_runner()->run_all();
		$stored  = array();
		$rows    = array();
		foreach ( $results as $id => $result ) {
			$stored[ $id ] = $result->to_array();
			$rows[]        = array(
				'id'     => $id,
				'status' => $result->status(),
				'label'  => $result->label(),
				'detail' => $result->description(),
			);
		}
		ResultsCache::save( $stored );

		$format = isset( $assoc['format'] ) ? $assoc['format'] : 'table';
		\WP_CLI\Utils\format_items( 'json' === $format ? 'json' : 'table', $rows, array( 'id', 'status', 'label', 'detail' ) );
	}
}
