<?php
/**
 * Plugin Name: CF7 Spam Blocker
 * Description: 複数のWordPressサイトの迷惑メール対策を、1つのブロックリストで一括管理できるContact Form 7用スパムブロッカー。
 * Version: 2.9.0
 * Author: Hiroshi Yoshida
 * Requires at least: 5.8
 * Requires PHP: 7.4
 * Update URI: https://github.com/hiroshiy1227/tool-wp-spamblocker
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

define( 'CF7SB_VERSION', '2.9.0' );
define( 'CF7SB_FILE', __FILE__ );
define( 'CF7SB_DIR', plugin_dir_path( __FILE__ ) );

require_once CF7SB_DIR . 'includes/class-cf7sb-server.php';
require_once CF7SB_DIR . 'includes/class-cf7sb-blocklist.php';
require_once CF7SB_DIR . 'includes/class-cf7sb-validator.php';
require_once CF7SB_DIR . 'includes/class-cf7sb-updater.php';

CF7SB_Server::init();
CF7SB_Blocklist::init();
CF7SB_Validator::init();
CF7SB_Updater::init();

if ( is_admin() ) {
	require_once CF7SB_DIR . 'includes/class-cf7sb-admin.php';
	CF7SB_Admin::init();
}

register_activation_hook( __FILE__, array( 'CF7SB_Blocklist', 'activate' ) );
register_deactivation_hook( __FILE__, array( 'CF7SB_Blocklist', 'deactivate' ) );
