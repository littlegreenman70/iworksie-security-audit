<?php
/**
 * Uninstall cleanup for iWorks.ie Security Audit.
 *
 * @package IWorksIE\SecurityAudit
 */

defined( 'WP_UNINSTALL_PLUGIN' ) || exit;

global $wpdb;

wp_clear_scheduled_hook( 'iwiesa_weekly_audit' );

$iwiesa_prefix = 'iwiesa_';

// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
$iwiesa_options = $wpdb->get_col(
	$wpdb->prepare(
		"SELECT option_name FROM {$wpdb->options} WHERE option_name LIKE %s",
		$wpdb->esc_like( $iwiesa_prefix ) . '%'
	)
);

if ( is_array( $iwiesa_options ) ) {
	foreach ( $iwiesa_options as $iwiesa_option ) {
		delete_option( $iwiesa_option );
	}
}

// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
$iwiesa_transients = $wpdb->get_col(
	$wpdb->prepare(
		"SELECT option_name FROM {$wpdb->options} WHERE option_name LIKE %s OR option_name LIKE %s",
		$wpdb->esc_like( '_transient_' . $iwiesa_prefix ) . '%',
		$wpdb->esc_like( '_transient_timeout_' . $iwiesa_prefix ) . '%'
	)
);

if ( is_array( $iwiesa_transients ) ) {
	foreach ( $iwiesa_transients as $iwiesa_transient_option ) {
		if ( 0 === strpos( $iwiesa_transient_option, '_transient_timeout_' ) ) {
			$iwiesa_key = substr( $iwiesa_transient_option, strlen( '_transient_timeout_' ) );
			delete_transient( $iwiesa_key );
			continue;
		}
		if ( 0 === strpos( $iwiesa_transient_option, '_transient_' ) ) {
			$iwiesa_key = substr( $iwiesa_transient_option, strlen( '_transient_' ) );
			delete_transient( $iwiesa_key );
		}
	}
}

if ( is_multisite() ) {
	// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
	$iwiesa_site_options = $wpdb->get_col(
		$wpdb->prepare(
			"SELECT meta_key FROM {$wpdb->sitemeta} WHERE meta_key LIKE %s",
			$wpdb->esc_like( $iwiesa_prefix ) . '%'
		)
	);
	if ( is_array( $iwiesa_site_options ) ) {
		foreach ( $iwiesa_site_options as $iwiesa_site_option ) {
			delete_site_option( $iwiesa_site_option );
		}
	}
}
