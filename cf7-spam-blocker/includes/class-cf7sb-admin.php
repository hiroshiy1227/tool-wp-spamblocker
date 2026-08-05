<?php
/**
 * 設定画面（設定 → CF7 Spam Blocker）。
 * ・接続設定（このサイトにのみ保存）
 * ・ブロックリスト編集（中央サーバーに保存 → 同じリストを参照する全サイトに反映）
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class CF7SB_Admin {

	public static function init() {
		add_action( 'admin_menu', array( __CLASS__, 'add_menu' ) );
		add_action( 'admin_post_cf7sb_save_settings', array( __CLASS__, 'handle_save_settings' ) );
		add_action( 'admin_post_cf7sb_save_blocklist', array( __CLASS__, 'handle_save_blocklist' ) );
		add_action( 'admin_post_cf7sb_refresh', array( __CLASS__, 'handle_refresh' ) );
		add_action( 'admin_notices', array( __CLASS__, 'notices' ) );
	}

	public static function add_menu() {
		add_options_page(
			'CF7 Spam Blocker',
			'CF7 Spam Blocker',
			'manage_options',
			'cf7sb',
			array( __CLASS__, 'render_page' )
		);
	}

	private static function redirect_back( $notice ) {
		wp_safe_redirect( add_query_arg( 'cf7sb_notice', $notice, admin_url( 'options-general.php?page=cf7sb' ) ) );
		exit;
	}

	public static function handle_save_settings() {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( '権限がありません。' );
		}
		check_admin_referer( 'cf7sb_save_settings' );

		$settings = CF7SB_Blocklist::get_settings();

		$settings['url']     = esc_url_raw( isset( $_POST['cf7sb_url'] ) ? trim( wp_unslash( $_POST['cf7sb_url'] ) ) : '' );
		$settings['key']     = sanitize_text_field( isset( $_POST['cf7sb_key'] ) ? wp_unslash( $_POST['cf7sb_key'] ) : '' );
		$settings['message'] = sanitize_text_field( isset( $_POST['cf7sb_message'] ) ? wp_unslash( $_POST['cf7sb_message'] ) : '' );
		if ( '' === $settings['message'] ) {
			$settings['message'] = '送信できない内容が含まれています。';
		}

		update_option( CF7SB_Blocklist::OPTION_SETTINGS, $settings, false );

		// URL変更直後に取得を試す
		if ( $settings['url'] ) {
			CF7SB_Blocklist::refresh();
		}

		self::redirect_back( 'settings_saved' );
	}

	public static function handle_save_blocklist() {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( '権限がありません。' );
		}
		check_admin_referer( 'cf7sb_save_blocklist' );

		$domains  = self::textarea_to_array( isset( $_POST['cf7sb_domains'] ) ? wp_unslash( $_POST['cf7sb_domains'] ) : '' );
		$keywords = self::textarea_to_array( isset( $_POST['cf7sb_keywords'] ) ? wp_unslash( $_POST['cf7sb_keywords'] ) : '' );

		$pushed = CF7SB_Blocklist::push( $domains, $keywords );
		if ( is_wp_error( $pushed ) ) {
			set_transient( 'cf7sb_last_error_' . get_current_user_id(), $pushed->get_error_message(), MINUTE_IN_SECONDS );
			self::redirect_back( 'push_failed' );
		}

		self::redirect_back( 'blocklist_saved' );
	}

	public static function handle_refresh() {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( '権限がありません。' );
		}
		check_admin_referer( 'cf7sb_refresh' );

		$refreshed = CF7SB_Blocklist::refresh();
		if ( is_wp_error( $refreshed ) ) {
			set_transient( 'cf7sb_last_error_' . get_current_user_id(), $refreshed->get_error_message(), MINUTE_IN_SECONDS );
			self::redirect_back( 'refresh_failed' );
		}

		self::redirect_back( 'refreshed' );
	}

	private static function textarea_to_array( $text ) {
		return CF7SB_Blocklist::sanitize_lines( preg_split( '/\r\n|\r|\n/', (string) $text ) );
	}

	public static function notices() {
		if ( empty( $_GET['cf7sb_notice'] ) || ! current_user_can( 'manage_options' ) ) {
			return;
		}

		$notice = sanitize_key( wp_unslash( $_GET['cf7sb_notice'] ) );
		$error  = get_transient( 'cf7sb_last_error_' . get_current_user_id() );
		delete_transient( 'cf7sb_last_error_' . get_current_user_id() );

		$messages = array(
			'settings_saved'  => array( 'success', '接続設定を保存しました。' ),
			'blocklist_saved' => array( 'success', 'ブロックリストを中央サーバーに保存しました。同じリストを参照する全サイトに反映されます（各サイトの次回取得時）。' ),
			'refreshed'       => array( 'success', 'ブロックリストを再取得しました。' ),
			'push_failed'     => array( 'error', 'ブロックリストの保存に失敗しました。' . ( $error ? '（' . $error . '）' : '' ) ),
			'refresh_failed'  => array( 'error', 'ブロックリストの取得に失敗しました。' . ( $error ? '（' . $error . '）' : '' ) ),
		);

		if ( ! isset( $messages[ $notice ] ) ) {
			return;
		}

		printf(
			'<div class="notice notice-%s is-dismissible"><p>%s</p></div>',
			esc_attr( $messages[ $notice ][0] ),
			esc_html( $messages[ $notice ][1] )
		);
	}

	public static function render_page() {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}

		$settings = CF7SB_Blocklist::get_settings();
		$stored   = get_option( CF7SB_Blocklist::OPTION_LIST, array() );
		$list     = CF7SB_Blocklist::get();
		$can_edit = ( '' !== $settings['key'] );

		$fetched_at = ! empty( $stored['fetched_at'] )
			? wp_date( 'Y-m-d H:i:s', $stored['fetched_at'] )
			: '未取得';
		$fetch_error = ! empty( $stored['error'] ) ? $stored['error'] : '';
		?>
		<div class="wrap">
			<h1>CF7 Spam Blocker</h1>

			<h2>接続設定</h2>
			<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
				<?php wp_nonce_field( 'cf7sb_save_settings' ); ?>
				<input type="hidden" name="action" value="cf7sb_save_settings">
				<table class="form-table" role="presentation">
					<tr>
						<th scope="row"><label for="cf7sb_url">ブロックリストURL</label></th>
						<td>
							<input type="url" id="cf7sb_url" name="cf7sb_url" class="regular-text code"
								value="<?php echo esc_attr( $settings['url'] ); ?>"
								placeholder="https://example.com/cf7sb/blocklist-api.php?list=default">
							<p class="description">中央サーバーの blocklist-api.php のURL。<code>?list=会社A</code> のようにリスト名を変えると、サイトごとに別のリストを共有できます。</p>
						</td>
					</tr>
					<tr>
						<th scope="row"><label for="cf7sb_key">書き込み用秘密キー</label></th>
						<td>
							<input type="password" id="cf7sb_key" name="cf7sb_key" class="regular-text"
								value="<?php echo esc_attr( $settings['key'] ); ?>" autocomplete="new-password">
							<p class="description">blocklist-api.php に設定したキー。空の場合、このサイトからは閲覧のみ（編集不可）になります。</p>
						</td>
					</tr>
					<tr>
						<th scope="row"><label for="cf7sb_message">ブロック時のエラーメッセージ</label></th>
						<td>
							<input type="text" id="cf7sb_message" name="cf7sb_message" class="regular-text"
								value="<?php echo esc_attr( $settings['message'] ); ?>">
						</td>
					</tr>
				</table>
				<?php submit_button( '接続設定を保存' ); ?>
			</form>

			<hr>

			<h2>ブロックリスト</h2>
			<p>
				最終取得: <strong><?php echo esc_html( $fetched_at ); ?></strong>
				（拒否ドメイン <?php echo count( $list['domains'] ); ?> 件 / 拒否文字列 <?php echo count( $list['keywords'] ); ?> 件）
				<?php if ( $fetch_error ) : ?>
					<span style="color:#b32d2e;">取得エラー: <?php echo esc_html( $fetch_error ); ?>（前回取得分で動作中）</span>
				<?php endif; ?>
			</p>

			<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" style="display:inline-block; margin-bottom:1em;">
				<?php wp_nonce_field( 'cf7sb_refresh' ); ?>
				<input type="hidden" name="action" value="cf7sb_refresh">
				<?php submit_button( '今すぐ再取得', 'secondary', 'submit', false ); ?>
			</form>

			<?php if ( ! $can_edit ) : ?>
				<div class="notice notice-info inline"><p>書き込み用秘密キーが未設定のため、このサイトからは編集できません（自動取得は動作します）。</p></div>
			<?php endif; ?>

			<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
				<?php wp_nonce_field( 'cf7sb_save_blocklist' ); ?>
				<input type="hidden" name="action" value="cf7sb_save_blocklist">
				<table class="form-table" role="presentation">
					<tr>
						<th scope="row"><label for="cf7sb_domains">拒否ドメイン（1行1件）</label></th>
						<td>
							<textarea id="cf7sb_domains" name="cf7sb_domains" rows="8" class="large-text code"
								<?php disabled( ! $can_edit ); ?>><?php echo esc_textarea( implode( "\n", $list['domains'] ) ); ?></textarea>
							<p class="description">メール欄はサブドメイン含む完全一致、本文・テキスト欄は文字列として含まれていればブロックします。例: <code>saleslist-x.com</code></p>
						</td>
					</tr>
					<tr>
						<th scope="row"><label for="cf7sb_keywords">拒否文字列（1行1件）</label></th>
						<td>
							<textarea id="cf7sb_keywords" name="cf7sb_keywords" rows="8" class="large-text code"
								<?php disabled( ! $can_edit ); ?>><?php echo esc_textarea( implode( "\n", $list['keywords'] ) ); ?></textarea>
							<p class="description">本文・テキスト欄にこの文字列（会社名など）が含まれていればブロックします。</p>
						</td>
					</tr>
				</table>
				<?php if ( $can_edit ) : ?>
					<?php submit_button( 'ブロックリストを保存（全サイトに反映）' ); ?>
				<?php endif; ?>
			</form>
		</div>
		<?php
	}
}
