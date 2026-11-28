<?php
/**
 * Admin screen: Audit, Report and Settings tabs.
 *
 * @package IWorksIE\SecurityAudit
 */

namespace IWorksIE\SecurityAudit\Admin;

use IWorksIE\SecurityAudit\Support\ReportBuilder;
use IWorksIE\SecurityAudit\Support\ResultsCache;
use IWorksIE\SecurityAudit\Support\Settings;
use IWorksIE\SecurityAudit\Support\WeeklyEmail;
use IWorksIE\SecurityAudit\Vendor\IWorksIE\Core\Checks\Result;
use IWorksIE\SecurityAudit\Vendor\IWorksIE\Core\Core;
use IWorksIE\SecurityAudit\Vendor\IWorksIE\Core\Strings;
use IWorksIE\SecurityAudit\Vendor\IWorksIE\Core\UI;

/**
 * Renders the plugin page.
 */
final class Screens {

	/**
	 * @var Core
	 */
	private $core;

	/**
	 * @param Core $core Core.
	 */
	public function __construct( Core $core ) {
		$this->core = $core;
	}

	/**
	 * Menu callback.
	 *
	 * @return void
	 */
	public function render() {
		if ( ! current_user_can( (string) $this->core->config( 'capability' ) ) ) {
			wp_die( esc_html__( 'Sorry, you are not allowed to access this page.', 'iworksie-security-audit' ) );
		}

		$this->core->page()->render(
			array(
				'title'   => (string) $this->core->config( 'name' ),
				'version' => (string) $this->core->config( 'version' ),
				'tagline' => (string) $this->core->config( 'tagline' ),
				'tabs'    => array(
					'audit'    => __( 'Audit', 'iworksie-security-audit' ),
					'report'   => __( 'Report', 'iworksie-security-audit' ),
					'settings' => __( 'Settings', 'iworksie-security-audit' ),
				),
			),
			function ( $active ) {
				switch ( $active ) {
					case 'report':
						$this->render_report();
						break;
					case 'settings':
						$this->render_settings();
						break;
					default:
						$this->render_audit();
						break;
				}
			}
		);
	}

	/**
	 * @return void
	 */
	private function render_audit() {
		$cache       = ResultsCache::load();
		$has_results = null !== $cache && ! empty( $cache['results'] );
		$about       = __( 'The audit runs only when you click the button. It reads your settings and files, requests a few addresses on your own site the way a logged-out visitor would, and looks up your plugins on WordPress.org. It never changes anything.', 'iworksie-security-audit' );

		echo '<p class="iwiesa-last-checked">' . esc_html( ResultsCache::last_checked_label() ) . '</p>';

		if ( ! $has_results ) {
			echo '<div class="iwt-empty" data-iwt-empty>';
			echo '<div class="iwt-empty__icon" aria-hidden="true"><span class="dashicons dashicons-shield"></span></div>';
			echo '<h2 class="iwt-empty__title">' . esc_html__( 'Run your first security audit', 'iworksie-security-audit' ) . '</h2>';
			echo '<p class="iwt-empty__body">' . esc_html( $about ) . '</p>';
			echo '<p class="iwt-empty__action"><button type="button" class="button button-primary button-hero" data-iwiesa-run-audit="1">' . esc_html__( 'Run audit', 'iworksie-security-audit' ) . '</button></p>';
			echo '</div>';
			echo '<div class="iwt-summary-wrap" data-iwt-summary-wrap hidden>';
			echo UI::summary_bar( 0, 0, 0, 0 ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- UI escapes.
			echo '</div>';
			echo '<div data-iwt-results aria-live="polite" aria-label="' . esc_attr__( 'Security audit results', 'iworksie-security-audit' ) . '"></div>';
			return;
		}

		$grouped = array(
			'critical'    => array(),
			'recommended' => array(),
			'info'        => array(),
			'good'        => array(),
		);
		foreach ( $cache['results'] as $id => $row ) {
			$result                    = Result::from_array( (array) $row );
			$status                    = isset( $grouped[ $result->status() ] ) ? $result->status() : 'info';
			$grouped[ $status ][ $id ] = $result;
		}

		echo '<div class="iwt-toolbar">';
		echo '<button type="button" class="button button-primary" data-iwiesa-run-audit="1">' . esc_html__( 'Run audit again', 'iworksie-security-audit' ) . '</button>';
		echo '<p class="description iwiesa-about">' . esc_html( $about ) . '</p>';
		echo '</div>';
		echo '<div class="iwt-summary-wrap" data-iwt-summary-wrap>';
		echo UI::summary_bar( count( $grouped['good'] ), count( $grouped['recommended'] ), count( $grouped['critical'] ), count( $grouped['info'] ) ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- UI escapes.
		echo '</div>';
		echo '<div data-iwt-results aria-live="polite" aria-label="' . esc_attr__( 'Security audit results', 'iworksie-security-audit' ) . '">';
		foreach ( $grouped as $status => $results ) {
			if ( empty( $results ) ) {
				continue;
			}
			$count = count( $results );
			echo '<section class="iwt-group iwt-group--' . esc_attr( $status ) . ( 'good' === $status ? ' is-collapsed' : '' ) . '" data-group="' . esc_attr( $status ) . '">';
			if ( 'good' === $status ) {
				echo '<button type="button" class="iwt-group__toggle" aria-expanded="false" data-iwt-group-toggle>' . esc_html( Strings::get( 'passed_checks', array( 'count' => (string) $count ) ) ) . '</button>';
			} else {
				echo UI::group_heading( $status, $count ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- UI escapes.
			}
			echo '<div class="iwt-group__results">';
			foreach ( $results as $result ) {
				echo UI::result_card( $result, 'critical' === $status ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- UI escapes.
			}
			echo '</div></section>';
		}
		echo '</div>';
	}

	/**
	 * @return void
	 */
	private function render_report() {
		$cache = ResultsCache::load();
		if ( null === $cache ) {
			echo '<p>' . esc_html__( 'Run the audit first, then come back here to copy or download the report.', 'iworksie-security-audit' ) . '</p>';
			return;
		}
		$markdown = ReportBuilder::build( $cache['results'] );
		$url      = $this->core->report()->store_for_download( $markdown );

		echo '<div class="notice notice-info inline"><p>' . esc_html__( 'Send this report to your developer or host. It lists file names and plugin names, but never passwords, keys or salts. Treat it as private: it describes weak spots in your site.', 'iworksie-security-audit' ) . '</p></div>';
		echo '<div class="iwt-report-actions iwt-toolbar">';
		echo '<button type="button" class="button button-primary" data-iwt-copy="iwiesa-report-source">' . esc_html( Strings::get( 'copy_report' ) ) . '</button>';
		echo '<a class="button" href="' . esc_url( $url ) . '" data-iwt-download-report download="iworksie-security-audit-report.md">' . esc_html( Strings::get( 'download_report' ) ) . '</a>';
		echo '</div>';
		echo '<pre id="iwiesa-report-source" class="iwt-report-box iwiesa-report">' . esc_html( $markdown ) . '</pre>';
	}

	/**
	 * @return void
	 */
	private function render_settings() {
		$settings = Settings::get();
		$next     = wp_next_scheduled( WeeklyEmail::HOOK );

		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- display-only flag after our own redirect.
		if ( isset( $_GET['updated'] ) ) {
			echo '<div class="notice notice-success inline"><p>' . esc_html__( 'Settings saved.', 'iworksie-security-audit' ) . '</p></div>';
		}

		echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '" class="iwt-card iwiesa-settings">';
		echo '<input type="hidden" name="action" value="' . esc_attr( Settings::ACTION ) . '">';
		wp_nonce_field( Settings::ACTION );
		echo '<h2>' . esc_html__( 'Weekly audit email', 'iworksie-security-audit' ) . '</h2>';
		echo '<p>' . esc_html__( 'Off by default. When on, WordPress runs the audit once a week in the background and sends one short summary email. Nothing else runs in the background.', 'iworksie-security-audit' ) . '</p>';
		echo '<table class="form-table" role="presentation"><tbody>';

		echo '<tr><th scope="row">' . esc_html__( 'Weekly email', 'iworksie-security-audit' ) . '</th><td>';
		echo '<label><input type="checkbox" name="iwiesa_weekly_email" value="1"' . checked( $settings['weekly_email'], true, false ) . '> ' . esc_html__( 'Run the audit weekly and email me a summary', 'iworksie-security-audit' ) . '</label>';
		if ( false !== $next ) {
			echo '<p class="description">' . esc_html(
				sprintf(
					/* translators: %s: date and time */
					__( 'Next run: %s', 'iworksie-security-audit' ),
					wp_date( get_option( 'date_format' ) . ' ' . get_option( 'time_format' ), (int) $next )
				)
			) . '</p>';
		}
		echo '</td></tr>';

		echo '<tr><th scope="row">' . esc_html__( 'Only when needed', 'iworksie-security-audit' ) . '</th><td>';
		echo '<label><input type="checkbox" name="iwiesa_only_issues" value="1"' . checked( $settings['only_issues'], true, false ) . '> ' . esc_html__( 'Only send the email when something is Critical or Recommended', 'iworksie-security-audit' ) . '</label>';
		echo '</td></tr>';

		echo '<tr><th scope="row"><label for="iwiesa-email">' . esc_html__( 'Send to', 'iworksie-security-audit' ) . '</label></th><td>';
		echo '<input type="email" class="regular-text" id="iwiesa-email" name="iwiesa_email" value="' . esc_attr( $settings['email'] ) . '" placeholder="' . esc_attr( (string) get_option( 'admin_email' ) ) . '">';
		echo '<p class="description">' . esc_html__( 'Leave empty to use the site admin email address.', 'iworksie-security-audit' ) . '</p>';
		echo '</td></tr>';

		echo '</tbody></table>';
		submit_button( __( 'Save settings', 'iworksie-security-audit' ) );
		echo '</form>';
	}
}
