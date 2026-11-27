<?php
/**
 * Plugins closed on WordPress.org or not updated in two years.
 *
 * @package IWorksIE\SecurityAudit
 */

namespace IWorksIE\SecurityAudit\Checks\Software;

use IWorksIE\SecurityAudit\Checks\BaseCheck;
use IWorksIE\SecurityAudit\Support\WporgPlugins;
use IWorksIE\SecurityAudit\Vendor\IWorksIE\Core\Checks\Result;

/**
 * Closed / abandoned plugin detection.
 */
final class AbandonedPluginsCheck extends BaseCheck {

	/**
	 * Seconds without an update before a plugin counts as abandoned (2 years).
	 */
	const STALE_AFTER = 2 * YEAR_IN_SECONDS;

	/** @return string */
	public function id() {
		return 'abandoned_plugins';
	}

	/** @return string */
	public function label() {
		return __( 'Closed or abandoned plugins', 'iworksie-security-audit' );
	}

	/** @return string */
	public function group() {
		return 'software';
	}

	/** @return Result */
	public function run() {
		$why = __( 'WordPress.org closes plugins that have unfixed security problems or break its rules, and closed plugins never get another update. Plugins nobody has touched in two years are also unlikely to get a fix when a hole is found.', 'iworksie-security-audit' );
		$fix = __( 'Replace each one with a maintained plugin that does the same job, then delete it. If a plugin was closed for a security issue, deal with it today.', 'iworksie-security-audit' );

		$installed = WporgPlugins::installed();
		if ( empty( $installed ) ) {
			return $this->result(
				'info',
				__( 'No plugins from WordPress.org were found to look up (or WordPress has not checked for plugin updates yet). Premium and custom plugins are not checked.', 'iworksie-security-audit' ),
				$why,
				__( 'Open Dashboard > Updates and click "Check again", then run the audit again.', 'iworksie-security-audit' )
			);
		}

		$slugs = array();
		foreach ( $installed as $plugin ) {
			$slugs[] = $plugin['slug'];
		}
		$info = WporgPlugins::lookup( $slugs );

		$critical = false;
		$matches  = array();
		$unknown  = 0;
		$now      = time();
		foreach ( $installed as $plugin ) {
			$slug = sanitize_key( $plugin['slug'] );
			$row  = isset( $info[ $slug ] ) ? $info[ $slug ] : null;
			if ( null === $row || 'unknown' === $row['status'] ) {
				++$unknown;
				continue;
			}
			if ( 'closed' === $row['status'] ) {
				$security  = 'security-issue' === $row['reason'];
				$critical  = $critical || $security;
				$matches[] = array(
					'relative' => $plugin['name'],
					'kind'     => $security ? __( 'Closed: security issue', 'iworksie-security-audit' ) : __( 'Closed on WordPress.org', 'iworksie-security-audit' ),
				);
				continue;
			}
			if ( 'ok' === $row['status'] && $row['last_updated'] > 0 && ( $now - $row['last_updated'] ) > self::STALE_AFTER ) {
				$matches[] = array(
					'relative' => $plugin['name'],
					'kind'     => sprintf(
						/* translators: %s: human time, e.g. "3 years" */
						__( 'Last updated %s ago', 'iworksie-security-audit' ),
						human_time_diff( $row['last_updated'], $now )
					),
				);
			}
		}

		$note = '';
		if ( $unknown > 0 ) {
			$note = ' ' . sprintf(
				/* translators: %d: number of plugins */
				_n( '%d plugin could not be looked up this time; run the audit again to finish.', '%d plugins could not be looked up this time; run the audit again to finish.', $unknown, 'iworksie-security-audit' ),
				$unknown
			);
		}

		if ( ! empty( $matches ) ) {
			return $this->result(
				$critical ? 'critical' : 'recommended',
				sprintf(
					/* translators: %d: number of plugins */
					_n( '%d installed plugin is closed or has not been updated in over two years.', '%d installed plugins are closed or have not been updated in over two years.', count( $matches ), 'iworksie-security-audit' ),
					count( $matches )
				) . $note,
				$why,
				$fix,
				array( 'matches' => $matches )
			);
		}
		if ( count( $installed ) === $unknown ) {
			return $this->result(
				'info',
				__( 'Could not reach WordPress.org to look up your plugins.', 'iworksie-security-audit' ),
				$why,
				__( 'Run the audit again later. If it keeps failing, your host may block outgoing requests.', 'iworksie-security-audit' )
			);
		}
		return $this->result(
			'good',
			sprintf(
				/* translators: %d: number of plugins */
				_n( 'The %d plugin from WordPress.org is open and maintained.', 'All %d plugins from WordPress.org are open and maintained.', count( $installed ) - $unknown, 'iworksie-security-audit' ),
				count( $installed ) - $unknown
			) . $note,
			$why,
			$this->no_action()
		);
	}
}
