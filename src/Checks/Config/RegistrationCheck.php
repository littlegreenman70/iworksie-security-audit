<?php
/**
 * Open registration with a powerful default role.
 *
 * @package IWorksIE\SecurityAudit
 */

namespace IWorksIE\SecurityAudit\Checks\Config;

use IWorksIE\SecurityAudit\Checks\BaseCheck;
use IWorksIE\SecurityAudit\Vendor\IWorksIE\Core\Checks\Result;

/**
 * users_can_register + default_role.
 */
final class RegistrationCheck extends BaseCheck {

	/** @return string */
	public function id() {
		return 'registration';
	}

	/** @return string */
	public function label() {
		return __( 'New user sign-ups', 'iworksie-security-audit' );
	}

	/** @return string */
	public function group() {
		return 'config';
	}

	/** @return Result */
	public function run() {
		$open    = (bool) get_option( 'users_can_register' );
		$role    = (string) get_option( 'default_role', 'subscriber' );
		$why     = __( 'Attackers look for sites where anyone can register and get more than a basic account. A sign-up that becomes an Editor or Administrator hands over the site.', 'iworksie-security-audit' );
		$data    = array(
			'open'         => $open,
			'default_role' => $role,
		);
		$actions = array( $this->action( __( 'Open General Settings', 'iworksie-security-audit' ), 'options-general.php' ) );

		if ( ! $open ) {
			return $this->result( 'good', __( 'Anyone can register is switched off.', 'iworksie-security-audit' ), $why, $this->no_action(), $data );
		}

		$role_obj = get_role( $role );
		$powerful = null !== $role_obj && ( $role_obj->has_cap( 'edit_others_posts' ) || $role_obj->has_cap( 'manage_options' ) || $role_obj->has_cap( 'edit_users' ) || $role_obj->has_cap( 'unfiltered_html' ) || $role_obj->has_cap( 'upload_files' ) );
		if ( $powerful ) {
			return $this->result(
				'critical',
				sprintf(
					/* translators: %s: role name */
					__( 'Anyone can register, and new users get the "%s" role, which can do far more than a basic account.', 'iworksie-security-audit' ),
					$role
				),
				$why,
				__( 'Under Settings > General set "New User Default Role" to Subscriber (or Customer for shops). If nobody needs to register, untick "Anyone can register". Then check the user list for accounts you do not recognise.', 'iworksie-security-audit' ),
				$data,
				$actions
			);
		}
		return $this->result(
			'info',
			sprintf(
				/* translators: %s: role name */
				__( 'Anyone can register, and new users get the "%s" role. That is normal for shops and membership sites.', 'iworksie-security-audit' ),
				$role
			),
			$why,
			__( 'If your site does not need public sign-ups, untick "Anyone can register" under Settings > General to cut down on spam accounts.', 'iworksie-security-audit' ),
			$data,
			$actions
		);
	}
}
