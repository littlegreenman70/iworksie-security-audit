<?php
/**
 * Plugin bootstrap.
 *
 * @package IWorksIE\SecurityAudit
 */

namespace IWorksIE\SecurityAudit;

use IWorksIE\SecurityAudit\Admin\Ajax;
use IWorksIE\SecurityAudit\Admin\Screens;
use IWorksIE\SecurityAudit\Checks\Access\AdminUsernameCheck;
use IWorksIE\SecurityAudit\Checks\Access\LoginProtectionCheck;
use IWorksIE\SecurityAudit\Checks\Access\UserEnumerationCheck;
use IWorksIE\SecurityAudit\Checks\Access\XmlRpcCheck;
use IWorksIE\SecurityAudit\Checks\Config\AutoUpdatesCheck;
use IWorksIE\SecurityAudit\Checks\Config\DebugDisplayCheck;
use IWorksIE\SecurityAudit\Checks\Config\DirectoryListingCheck;
use IWorksIE\SecurityAudit\Checks\Config\FileEditorCheck;
use IWorksIE\SecurityAudit\Checks\Config\HttpsCheck;
use IWorksIE\SecurityAudit\Checks\Config\RegistrationCheck;
use IWorksIE\SecurityAudit\Checks\Config\SecurityKeysCheck;
use IWorksIE\SecurityAudit\Checks\Exposure\BackupFilesCheck;
use IWorksIE\SecurityAudit\Checks\Exposure\LogFilesCheck;
use IWorksIE\SecurityAudit\Checks\Exposure\SecretFilesCheck;
use IWorksIE\SecurityAudit\Checks\Exposure\VersionControlCheck;
use IWorksIE\SecurityAudit\Checks\Server\FilePermissionsCheck;
use IWorksIE\SecurityAudit\Checks\Server\SecurityHeadersCheck;
use IWorksIE\SecurityAudit\Checks\Software\AbandonedPluginsCheck;
use IWorksIE\SecurityAudit\Checks\Software\CoreUpdatesCheck;
use IWorksIE\SecurityAudit\Checks\Software\ExtensionUpdatesCheck;
use IWorksIE\SecurityAudit\Checks\Software\InactiveCodeCheck;
use IWorksIE\SecurityAudit\Checks\Software\PhpVersionCheck;
use IWorksIE\SecurityAudit\Cli\Command;
use IWorksIE\SecurityAudit\Support\Settings;
use IWorksIE\SecurityAudit\Support\WeeklyEmail;
use IWorksIE\SecurityAudit\Vendor\IWorksIE\Core\Core;

/**
 * Singleton plugin entry.
 */
final class Plugin {

	/**
	 * @var self|null
	 */
	private static $instance = null;

	/**
	 * @var Core|null
	 */
	private $core = null;

	/**
	 * @return self
	 */
	public static function instance() {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	/**
	 * @return Core|null
	 */
	public function core() {
		return $this->core;
	}

	/**
	 * Boot core, checks, menu, AJAX, settings and the optional weekly email.
	 *
	 * @return void
	 */
	public function boot() {
		if ( null !== $this->core ) {
			return;
		}

		$cap = is_multisite() ? 'manage_network_options' : 'manage_options';

		$this->core = Core::boot(
			array(
				'plugin_file' => IWIESA_FILE,
				'slug'        => 'iworksie-security-audit',
				'prefix'      => 'iwiesa',
				'name'        => __( 'Security Audit', 'iworksie-security-audit' ),
				'version'     => IWIESA_VERSION,
				'text_domain' => 'iworksie-security-audit',
				'capability'  => $cap,
				'wporg_url'   => 'https://wordpress.org/plugins/iworksie-security-audit/',
				'description' => __( 'Finds exposed backups and config files, risky settings and abandoned plugins, with plain-English fixes.', 'iworksie-security-audit' ),
				'icon'        => 'dashicons-shield',
				'tagline'     => __( 'An audit, not a firewall: runs only when you ask and never changes your site.', 'iworksie-security-audit' ),
			)
		);

		foreach ( self::checks() as $check ) {
			$this->core->checks()->add( $check );
		}

		$screens = new Screens( $this->core );
		$this->core->menu()->add_submenu(
			__( 'Security Audit', 'iworksie-security-audit' ),
			__( 'Security Audit', 'iworksie-security-audit' ),
			'iworksie-security-audit',
			array( $screens, 'render' )
		);

		$ajax = new Ajax( $this->core );
		$ajax->hooks();

		Settings::hooks( $cap );
		add_action( WeeklyEmail::HOOK, array( WeeklyEmail::class, 'run' ) );
		add_action( 'admin_enqueue_scripts', array( $this, 'enqueue_assets' ) );
		Command::register();
	}

	/**
	 * Plugin JS/CSS on our screen only.
	 *
	 * @param string $hook Hook suffix.
	 * @return void
	 */
	public function enqueue_assets( $hook ) {
		if ( null === $this->core || false === strpos( (string) $hook, 'iworksie-security-audit' ) ) {
			return;
		}
		wp_enqueue_script(
			'iwiesa-admin',
			IWIESA_URL . 'assets/js/admin.js',
			array( 'iwiesa-iwt-core' ),
			IWIESA_VERSION,
			true
		);
		wp_localize_script(
			'iwiesa-admin',
			'iwiesaAdmin',
			array(
				'ajaxUrl' => admin_url( 'admin-ajax.php' ),
				'strings' => array(
					/* translators: 1: current check number, 2: total checks */
					'progress' => __( 'Checking {current} of {total}…', 'iworksie-security-audit' ),
					'failed'   => __( 'This check could not run. Try again.', 'iworksie-security-audit' ),
					'runAudit' => __( 'Run audit', 'iworksie-security-audit' ),
				),
			)
		);
		wp_enqueue_style(
			'iwiesa-admin',
			IWIESA_URL . 'assets/css/admin.css',
			array( 'iwiesa-iwt-core' ),
			IWIESA_VERSION
		);
	}

	/**
	 * All checks, in display order (cheap local checks first, network checks last).
	 *
	 * @return array<int,\IWorksIE\SecurityAudit\Checks\BaseCheck>
	 */
	public static function checks() {
		return array(
			new CoreUpdatesCheck(),
			new ExtensionUpdatesCheck(),
			new PhpVersionCheck(),
			new InactiveCodeCheck(),
			new DebugDisplayCheck(),
			new FileEditorCheck(),
			new SecurityKeysCheck(),
			new HttpsCheck(),
			new RegistrationCheck(),
			new AutoUpdatesCheck(),
			new AdminUsernameCheck(),
			new LoginProtectionCheck(),
			new FilePermissionsCheck(),
			new SecretFilesCheck(),
			new BackupFilesCheck(),
			new VersionControlCheck(),
			new LogFilesCheck(),
			new DirectoryListingCheck(),
			new UserEnumerationCheck(),
			new XmlRpcCheck(),
			new SecurityHeadersCheck(),
			new AbandonedPluginsCheck(),
		);
	}
}
