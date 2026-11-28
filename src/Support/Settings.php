<?php
/**
 * The plugin's own settings (weekly email). The only thing this plugin saves.
 *
 * @package IWorksIE\SecurityAudit
 */

namespace IWorksIE\SecurityAudit\Support;

/**
 * Option storage, sanitising and the admin-post save handler.
 */
final class Settings {

	const OPTION = 'iwiesa_settings';
	const ACTION = 'iwiesa_save_settings';

	/**
	 * Capability required to save.
	 *
	 * @var string
	 */
	private static $capability = 'manage_options';

	/**
	 * @param string $capability Capability.
	 * @return void
	 */
	public static function hooks( $capability ) {
		self::$capability = (string) $capability;
		add_action( 'admin_post_' . self::ACTION, array( self::class, 'handle_save' ) );
	}

	/**
	 * Current settings with defaults.
	 *
	 * @return array{weekly_email:bool,only_issues:bool,email:string}
	 */
	public static function get() {
		$saved = get_option( self::OPTION, array() );
		return self::sanitize( is_array( $saved ) ? $saved : array() );
	}

	/**
	 * Clean user input. Pure apart from is_email().
	 *
	 * @param array<string,mixed> $input Raw values.
	 * @return array{weekly_email:bool,only_issues:bool,email:string}
	 */
	public static function sanitize( array $input ) {
		$email = isset( $input['email'] ) ? sanitize_email( (string) $input['email'] ) : '';
		return array(
			'weekly_email' => ! empty( $input['weekly_email'] ),
			'only_issues'  => ! array_key_exists( 'only_issues', $input ) || ! empty( $input['only_issues'] ),
			'email'        => ( '' !== $email && is_email( $email ) ) ? $email : '',
		);
	}

	/**
	 * Where the weekly email goes.
	 *
	 * @return string
	 */
	public static function recipient() {
		$settings = self::get();
		return '' !== $settings['email'] ? $settings['email'] : (string) get_option( 'admin_email' );
	}

	/**
	 * admin-post handler.
	 *
	 * @return void
	 */
	public static function handle_save() {
		if ( ! current_user_can( self::$capability ) ) {
			wp_die( esc_html__( 'Sorry, you are not allowed to change these settings.', 'iworksie-security-audit' ), 403 );
		}
		check_admin_referer( self::ACTION );

		$raw      = array(
			'weekly_email' => isset( $_POST['iwiesa_weekly_email'] ),
			'only_issues'  => isset( $_POST['iwiesa_only_issues'] ),
			'email'        => isset( $_POST['iwiesa_email'] ) ? sanitize_email( wp_unslash( (string) $_POST['iwiesa_email'] ) ) : '',
		);
		$settings = self::sanitize( $raw );
		update_option( self::OPTION, $settings, false );
		WeeklyEmail::sync_schedule( $settings['weekly_email'] );

		wp_safe_redirect(
			add_query_arg(
				array(
					'page'    => 'iworksie-security-audit',
					'tab'     => 'settings',
					'updated' => '1',
				),
				admin_url( 'admin.php' )
			)
		);
		exit;
	}
}
