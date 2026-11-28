<?php
/**
 * Optional weekly audit with one summary email (off by default).
 *
 * @package IWorksIE\SecurityAudit
 */

namespace IWorksIE\SecurityAudit\Support;

use IWorksIE\SecurityAudit\Plugin;
use IWorksIE\SecurityAudit\Vendor\IWorksIE\Core\Checks\Result;

/**
 * WP-Cron job.
 */
final class WeeklyEmail {

	const HOOK = 'iwiesa_weekly_audit';

	/**
	 * Schedule or clear the weekly event.
	 *
	 * @param bool $enabled Whether the email is on.
	 * @return void
	 */
	public static function sync_schedule( $enabled ) {
		$next = wp_next_scheduled( self::HOOK );
		if ( $enabled && false === $next ) {
			wp_schedule_event( time() + HOUR_IN_SECONDS, 'weekly', self::HOOK );
		} elseif ( ! $enabled && false !== $next ) {
			wp_clear_scheduled_hook( self::HOOK );
		}
	}

	/**
	 * Cron callback: run every check, store results, maybe email.
	 *
	 * @return void
	 */
	public static function run() {
		$settings = Settings::get();
		if ( ! $settings['weekly_email'] ) {
			wp_clear_scheduled_hook( self::HOOK );
			return;
		}
		$core = Plugin::instance()->core();
		if ( null === $core ) {
			return;
		}
		$results = $core->checks_runner()->run_all();
		$stored  = array();
		foreach ( $results as $id => $result ) {
			$stored[ $id ] = $result->to_array();
		}
		ResultsCache::save( $stored );

		$message = self::compose( $results );
		if ( $settings['only_issues'] && '' === $message['issues'] ) {
			return;
		}
		wp_mail( Settings::recipient(), $message['subject'], $message['body'] );
	}

	/**
	 * Build the email. Pure apart from site name/URL lookups.
	 *
	 * @param array<string,Result> $results Results.
	 * @return array{subject:string,body:string,issues:string}
	 */
	public static function compose( array $results ) {
		$counts = array(
			'critical'    => array(),
			'recommended' => array(),
			'good'        => array(),
			'info'        => array(),
		);
		foreach ( $results as $result ) {
			$status              = isset( $counts[ $result->status() ] ) ? $result->status() : 'info';
			$counts[ $status ][] = $result->label() . ': ' . $result->description();
		}

		$site    = wp_specialchars_decode( (string) get_bloginfo( 'name' ), ENT_QUOTES );
		$issues  = '';
		$lines   = array();
		$lines[] = sprintf(
			/* translators: 1: critical count, 2: recommended count, 3: good count */
			__( 'Weekly security audit: %1$d critical, %2$d recommended, %3$d good.', 'iworksie-security-audit' ),
			count( $counts['critical'] ),
			count( $counts['recommended'] ),
			count( $counts['good'] )
		);
		$lines[] = '';
		foreach ( array( 'critical', 'recommended' ) as $status ) {
			if ( empty( $counts[ $status ] ) ) {
				continue;
			}
			$heading = 'critical' === $status ? __( 'Critical', 'iworksie-security-audit' ) : __( 'Recommended', 'iworksie-security-audit' );
			$block   = $heading . "\n" . '- ' . implode( "\n- ", $counts[ $status ] ) . "\n";
			$issues .= $block;
			$lines[] = $block;
		}
		if ( '' === $issues ) {
			$lines[] = __( 'Nothing needs your attention this week.', 'iworksie-security-audit' );
			$lines[] = '';
		}
		$lines[] = sprintf(
			/* translators: %s: admin URL */
			__( 'Full details and fixes: %s', 'iworksie-security-audit' ),
			admin_url( 'admin.php?page=iworksie-security-audit' )
		);
		$lines[] = '';
		$lines[] = __( 'You get this email because the weekly audit is switched on in iWorks Tools > Security Audit > Settings.', 'iworksie-security-audit' );
		$lines[] = __( 'Need a hand fixing these? iWorks builds and looks after WordPress sites: https://www.iworks.ie', 'iworksie-security-audit' );

		$subject = '' === $issues
			? sprintf(
				/* translators: %s: site name */
				__( '[%s] Weekly security audit: all clear', 'iworksie-security-audit' ),
				$site
			)
			: sprintf(
				/* translators: 1: site name, 2: number of issues */
				__( '[%1$s] Weekly security audit: %2$d to look at', 'iworksie-security-audit' ),
				$site,
				count( $counts['critical'] ) + count( $counts['recommended'] )
			);

		return array(
			'subject' => $subject,
			'body'    => implode( "\n", $lines ),
			'issues'  => $issues,
		);
	}
}
