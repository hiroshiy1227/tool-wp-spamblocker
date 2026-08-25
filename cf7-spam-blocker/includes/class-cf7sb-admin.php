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
		add_action( 'admin_post_cf7sb_enable_server', array( __CLASS__, 'handle_enable_server' ) );
		add_action( 'admin_post_cf7sb_disable_server', array( __CLASS__, 'handle_disable_server' ) );
		add_action( 'admin_post_cf7sb_clear_logs', array( __CLASS__, 'handle_clear_logs' ) );
		add_action( 'admin_notices', array( __CLASS__, 'notices' ) );
	}

	public static function add_menu() {
		add_menu_page(
			'CF7 Spam Blocker',
			'Spam Blocker',
			'manage_options',
			'cf7sb',
			array( __CLASS__, 'render_page' ),
			'dashicons-shield',
			58.7
		);
	}

	private static function redirect_back( $notice, $tab = '' ) {
		$url = admin_url( 'admin.php?page=cf7sb' );
		if ( $tab ) {
			$url = add_query_arg( 'tab', $tab, $url );
		}
		wp_safe_redirect( add_query_arg( 'cf7sb_notice', $notice, $url ) );
		exit;
	}

	public static function handle_save_settings() {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( '権限がありません。' );
		}
		check_admin_referer( 'cf7sb_save_settings' );

		$settings = CF7SB_Blocklist::get_settings();

		// 誤設定防止: 中央サーバー以外のサイトでは、接続済みならURL・キーの直接編集を受け付けない
		// （変更はセットアップコードの貼り付けでのみ可能。中央サーバー自身と、未接続サイトの初回入力は許可）
		$locked = ! CF7SB_Server::is_enabled() && '' !== $settings['url'];
		if ( ! $locked ) {
			$settings['url'] = esc_url_raw( isset( $_POST['cf7sb_url'] ) ? trim( wp_unslash( $_POST['cf7sb_url'] ) ) : '' );
			$settings['key'] = sanitize_text_field( isset( $_POST['cf7sb_key'] ) ? wp_unslash( $_POST['cf7sb_key'] ) : '' );
		}
		// メッセージは v1.8.0 から中央リスト側の共通設定になったため、ここでは扱わない
		// （settings['message'] は中央未設定時のフォールバックとして保持）

		// セットアップコードが貼り付けられていれば、URL・キーをコードから一括設定
		$code = sanitize_text_field( isset( $_POST['cf7sb_setup_code'] ) ? wp_unslash( $_POST['cf7sb_setup_code'] ) : '' );
		if ( '' !== $code ) {
			$decoded = self::decode_setup_code( $code );
			if ( null === $decoded ) {
				set_transient( 'cf7sb_last_error_' . get_current_user_id(), 'セットアップコードの形式が正しくありません。', MINUTE_IN_SECONDS );
				self::redirect_back( 'code_invalid', 'connection' );
			}
			$settings['url'] = $decoded['url'];
			$settings['key'] = $decoded['key'];
		}

		update_option( CF7SB_Blocklist::OPTION_SETTINGS, $settings, false );

		// URL変更直後に取得を試す
		if ( $settings['url'] ) {
			CF7SB_Blocklist::refresh();
		}

		self::redirect_back( 'settings_saved', 'connection' );
	}

	public static function handle_save_blocklist() {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( '権限がありません。' );
		}
		check_admin_referer( 'cf7sb_save_blocklist' );

		$domains_text  = isset( $_POST['cf7sb_domains'] ) ? (string) wp_unslash( $_POST['cf7sb_domains'] ) : '';
		$emails_text   = isset( $_POST['cf7sb_emails'] ) ? (string) wp_unslash( $_POST['cf7sb_emails'] ) : '';
		$keywords_text = isset( $_POST['cf7sb_keywords'] ) ? (string) wp_unslash( $_POST['cf7sb_keywords'] ) : '';
		$patterns_text = isset( $_POST['cf7sb_patterns'] ) ? (string) wp_unslash( $_POST['cf7sb_patterns'] ) : '';
		$message_text  = isset( $_POST['cf7sb_block_message'] ) ? sanitize_text_field( wp_unslash( $_POST['cf7sb_block_message'] ) ) : '';
		if ( '' === $message_text ) {
			$message_text = '迷惑行為と判定されたため送信を拒否しました。';
		}
		$block_uuid = ! empty( $_POST['cf7sb_block_uuid'] );
		$block_link = ! empty( $_POST['cf7sb_block_link'] );

		$pending = array( 'domains' => $domains_text, 'emails' => $emails_text, 'keywords' => $keywords_text, 'patterns' => $patterns_text, 'message' => $message_text, 'block_uuid' => $block_uuid, 'block_link' => $block_link );

		// 正規表現として不正なパターンは保存前に弾いて知らせる（黙って消さない）
		$invalid_patterns = array();
		foreach ( preg_split( '/\r\n|\r|\n/', $patterns_text ) as $line ) {
			$line = trim( $line );
			if ( '' !== $line && false === @preg_match( CF7SB_Blocklist::wrap_pattern( $line ), '' ) ) {
				$invalid_patterns[] = $line;
			}
		}
		if ( $invalid_patterns ) {
			set_transient( 'cf7sb_last_error_' . get_current_user_id(), '正規表現として解釈できない拒否パターンがあります: ' . implode( ' ／ ', $invalid_patterns ), MINUTE_IN_SECONDS );
			set_transient( 'cf7sb_pending_input_' . get_current_user_id(), $pending, 10 * MINUTE_IN_SECONDS );
			self::redirect_back( 'push_failed', 'blocklist' );
		}

		$pushed = CF7SB_Blocklist::push(
			self::textarea_to_array( $domains_text ),
			self::textarea_to_array( $keywords_text ),
			self::textarea_to_array( $emails_text ),
			$message_text,
			preg_split( '/\r\n|\r|\n/', $patterns_text ),
			$block_uuid,
			$block_link
		);
		if ( is_wp_error( $pushed ) ) {
			set_transient( 'cf7sb_last_error_' . get_current_user_id(), $pushed->get_error_message(), MINUTE_IN_SECONDS );
			// 入力内容を消さないよう保持して、再表示時にフォームへ戻す
			set_transient( 'cf7sb_pending_input_' . get_current_user_id(), $pending, 10 * MINUTE_IN_SECONDS );
			self::redirect_back( 'push_failed', 'blocklist' );
		}

		delete_transient( 'cf7sb_pending_input_' . get_current_user_id() );
		self::redirect_back( 'blocklist_saved', 'blocklist' );
	}

	public static function handle_clear_logs() {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( '権限がありません。' );
		}
		check_admin_referer( 'cf7sb_clear_logs' );

		$cleared = CF7SB_Blocklist::clear_logs();
		if ( is_wp_error( $cleared ) ) {
			set_transient( 'cf7sb_last_error_' . get_current_user_id(), $cleared->get_error_message(), MINUTE_IN_SECONDS );
			self::redirect_back( 'logs_clear_failed', 'log' );
		}

		self::redirect_back( 'logs_cleared', 'log' );
	}

	public static function handle_refresh() {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( '権限がありません。' );
		}
		check_admin_referer( 'cf7sb_refresh' );

		$refreshed = CF7SB_Blocklist::refresh();
		if ( is_wp_error( $refreshed ) ) {
			set_transient( 'cf7sb_last_error_' . get_current_user_id(), $refreshed->get_error_message(), MINUTE_IN_SECONDS );
			self::redirect_back( 'refresh_failed', 'blocklist' );
		}

		self::redirect_back( 'refreshed', 'blocklist' );
	}

	/**
	 * このサイトを中央サーバーにする（かんたんセットアップ）。
	 */
	public static function handle_enable_server() {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( '権限がありません。' );
		}
		check_admin_referer( 'cf7sb_enable_server' );

		CF7SB_Server::enable();
		self::redirect_back( 'server_enabled', 'setup' );
	}

	public static function handle_disable_server() {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( '権限がありません。' );
		}
		check_admin_referer( 'cf7sb_disable_server' );

		CF7SB_Server::disable();
		self::redirect_back( 'server_disabled', 'setup' );
	}

	/**
	 * セットアップコード（URL＋キーをまとめた文字列）の生成と復元。
	 * 形式: CF7SB1:<base64({"url":"...","key":"..."})>
	 */
	public static function encode_setup_code( $url, $key ) {
		return 'CF7SB1:' . base64_encode( wp_json_encode( array( 'url' => $url, 'key' => $key ) ) );
	}

	private static function decode_setup_code( $code ) {
		if ( 0 !== strpos( $code, 'CF7SB1:' ) ) {
			return null;
		}
		$json = base64_decode( substr( $code, 7 ), true );
		if ( false === $json ) {
			return null;
		}
		$data = json_decode( $json, true );
		if ( ! is_array( $data ) || empty( $data['url'] ) || ! isset( $data['key'] ) ) {
			return null;
		}
		$url = esc_url_raw( $data['url'] );
		if ( '' === $url ) {
			return null;
		}
		return array(
			'url' => $url,
			'key' => sanitize_text_field( $data['key'] ),
		);
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
			'blocklist_saved' => array( 'success', 'ブロックリストを中央サーバーに保存しました。同じリストを参照する全サイトに即時反映されます。' ),
			'refreshed'       => array( 'success', 'ブロックリストを再取得しました。' ),
			'server_enabled'  => array( 'success', 'このサイトを中央サーバーにしました。他のサイトは、下の「セットアップコード」を貼り付けるだけで接続できます。' ),
			'server_disabled' => array( 'success', '中央サーバー機能を停止しました（保存済みのリストデータは残っています）。' ),
			'logs_cleared'    => array( 'success', 'ブロックログを消去しました。' ),
			'logs_clear_failed' => array( 'error', 'ブロックログを消去できませんでした。' . ( $error ? '（' . $error . '）' : '' ) ),
			'push_failed'     => array( 'error', 'ブロックリストの保存に失敗しました。' . ( $error ? '（' . $error . '）' : '' ) ),
			'code_invalid'    => array( 'error', 'セットアップコードを読み取れませんでした。コピー元のサイトで表示されたコードを、そのまま全部貼り付けてください。' ),
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

		// 表示するタブ（未指定時は、未設定サイトならセットアップ、設定済みならブロック設定）
		$tab = isset( $_GET['tab'] ) ? sanitize_key( wp_unslash( $_GET['tab'] ) ) : '';
		if ( ! in_array( $tab, array( 'setup', 'connection', 'blocklist', 'log' ), true ) ) {
			$tab = ( '' === $settings['url'] ) ? 'setup' : 'blocklist';
		}

		// ブロック設定タブを開いたら常に最新を取得（「今すぐ再取得」ボタンの代わり）
		if ( 'blocklist' === $tab && '' !== $settings['url'] ) {
			CF7SB_Blocklist::refresh();
		}

		$stored   = get_option( CF7SB_Blocklist::OPTION_LIST, array() );
		$list     = CF7SB_Blocklist::get();
		$can_edit = ( '' !== $settings['key'] );

		$fetched_at = ! empty( $stored['fetched_at'] )
			? wp_date( 'Y-m-d H:i:s', $stored['fetched_at'] )
			: '未取得';
		$fetch_error = ! empty( $stored['error'] ) ? $stored['error'] : '';

		// 直前の保存が失敗していた場合は、入力していた内容をフォームに復元する
		$pending       = get_transient( 'cf7sb_pending_input_' . get_current_user_id() );
		$has_pending   = is_array( $pending );
		$domains_text  = implode( "\n", $list['domains'] );
		$emails_text   = implode( "\n", $list['emails'] );
		$keywords_text = implode( "\n", $list['keywords'] );
		$patterns_text = implode( "\n", $list['patterns'] );
		$message_text  = CF7SB_Blocklist::get_message();
		if ( $has_pending ) {
			delete_transient( 'cf7sb_pending_input_' . get_current_user_id() );
			$domains_text  = isset( $pending['domains'] ) ? $pending['domains'] : $domains_text;
			$emails_text   = isset( $pending['emails'] ) ? $pending['emails'] : $emails_text;
			$keywords_text = isset( $pending['keywords'] ) ? $pending['keywords'] : $keywords_text;
			$patterns_text = isset( $pending['patterns'] ) ? $pending['patterns'] : $patterns_text;
			$message_text  = isset( $pending['message'] ) ? $pending['message'] : $message_text;
		}

		// 誤設定防止: 中央サーバー以外のサイトでは、接続済みならURL・キーは閲覧のみ
		$conn_locked = ! CF7SB_Server::is_enabled() && '' !== $settings['url'];

		$base_url = admin_url( 'admin.php?page=cf7sb' );
		?>
		<div class="wrap">
			<h1>CF7 Spam Blocker</h1>

			<h2 class="nav-tab-wrapper" style="margin-bottom:1.2em;">
				<a href="<?php echo esc_url( add_query_arg( 'tab', 'setup', $base_url ) ); ?>" class="nav-tab <?php echo 'setup' === $tab ? 'nav-tab-active' : ''; ?>">初期セットアップ</a>
				<a href="<?php echo esc_url( add_query_arg( 'tab', 'connection', $base_url ) ); ?>" class="nav-tab <?php echo 'connection' === $tab ? 'nav-tab-active' : ''; ?>">接続設定</a>
				<a href="<?php echo esc_url( add_query_arg( 'tab', 'blocklist', $base_url ) ); ?>" class="nav-tab <?php echo 'blocklist' === $tab ? 'nav-tab-active' : ''; ?>">ブロック設定</a>
				<a href="<?php echo esc_url( add_query_arg( 'tab', 'log', $base_url ) ); ?>" class="nav-tab <?php echo 'log' === $tab ? 'nav-tab-active' : ''; ?>">ブロックログ</a>
			</h2>

			<?php if ( 'setup' === $tab ) : ?>

			<?php if ( CF7SB_Server::is_enabled() ) : ?>
				<div style="padding:1em 1.4em; background:#fff; border-left:4px solid #00a32a; box-shadow:0 1px 1px rgba(0,0,0,.04); max-width:800px; margin-bottom:1em;">
					<p style="margin:0 0 0.6em; font-size:1.05em;"><span class="dashicons dashicons-yes-alt" style="color:#00a32a; vertical-align:text-bottom;"></span> <strong>このサイトは中央サーバーです。</strong>ブロックリストはこのサイトに保管され、接続した全サイトに配信されます。</p>
					<p style="margin:0 0 0.4em;"><strong>他のサイトを追加する手順（コピペ1回）</strong></p>
					<ol style="margin:0 0 1em;">
						<li>新しいサイトにこのプラグインをインストール・有効化</li>
						<li>下のセットアップコードをコピーし、新しいサイトの「接続設定」タブの「セットアップコード」欄に貼り付けて保存</li>
					</ol>
					<input type="text" readonly id="cf7sb_setup_code_out" class="large-text code"
						value="<?php echo esc_attr( self::encode_setup_code( $settings['url'], $settings['key'] ) ); ?>"
						onclick="this.select();">
					<button type="button" class="button button-primary" id="cf7sb_code_copy" style="margin-top:6px;">セットアップコードをコピー</button>
					<p class="description" style="margin:0.8em 0 0;">
						配信URL: <code><?php echo esc_html( $settings['url'] ); ?></code><br>
						動作確認: フォームのメール欄に拒否ドメインのアドレスを入力して送信し、「<?php echo esc_html( $message_text ); ?>」と表示されればOKです。
					</p>
					<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" style="margin:0.8em 0 0;">
						<?php wp_nonce_field( 'cf7sb_disable_server' ); ?>
						<input type="hidden" name="action" value="cf7sb_disable_server">
						<button type="submit" class="button button-link-delete" onclick="return confirm('中央サーバー機能を停止しますか？（リストのデータは残ります）');">中央サーバーを停止する</button>
					</form>
				</div>
			<?php else : ?>
				<div style="padding:1em 1.4em; background:#fff; border-left:4px solid #2271b1; box-shadow:0 1px 1px rgba(0,0,0,.04); max-width:800px; margin-bottom:1em;">
					<p style="margin:0 0 0.4em;"><strong>1サイト目（ブロックリストの保管場所にするサイト）:</strong></p>
					<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" style="margin:0 0 0.8em;">
						<?php wp_nonce_field( 'cf7sb_enable_server' ); ?>
						<input type="hidden" name="action" value="cf7sb_enable_server">
						<button type="submit" class="button button-primary button-hero">このサイトを中央サーバーにする</button>
					</form>
					<p class="description" style="margin:0 0 1em;">ボタンを押すだけで完了します。このサイトのWordPress内にリストが保管され、秘密キーと接続設定も自動で整います。</p>
					<p style="margin:0 0 0.4em;"><strong>2サイト目以降:</strong></p>
					<p class="description" style="margin:0;">中央サーバーにしたサイトの「初期セットアップ」タブでセットアップコードをコピーし、このサイトの「接続設定」タブに貼り付けて保存するだけです。</p>
				</div>
			<?php endif; ?>

			<?php endif; ?>

			<?php if ( 'connection' === $tab ) : ?>
			<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
				<?php wp_nonce_field( 'cf7sb_save_settings' ); ?>
				<input type="hidden" name="action" value="cf7sb_save_settings">
				<table class="form-table" role="presentation">
					<tr>
						<th scope="row"><label for="cf7sb_url">ブロックリストURL</label></th>
						<td>
							<input type="url" id="cf7sb_url" name="cf7sb_url" class="regular-text code"
								value="<?php echo esc_attr( $settings['url'] ); ?>"
								placeholder="https://example.com/wp-json/cf7sb/v1/list?list=default"
								<?php echo $conn_locked ? 'readonly style="background:#f0f0f1;"' : ''; ?>>
							<?php if ( $conn_locked ) : ?>
								<p class="description">誤設定防止のため閲覧のみです。変更する場合は、中央サーバーのサイトでコピーした<strong>セットアップコードを下に貼り付けて保存</strong>してください。</p>
							<?php else : ?>
								<p class="description">中央サーバーの配信URL。<code>?list=会社A</code> のようにリスト名を変えると、サイトごとに別のリストを共有できます。</p>
							<?php endif; ?>
						</td>
					</tr>
					<tr>
						<th scope="row"><label for="cf7sb_key">書き込み用秘密キー</label></th>
						<td>
							<input type="password" id="cf7sb_key" name="cf7sb_key" class="regular-text"
								value="<?php echo esc_attr( $settings['key'] ); ?>" autocomplete="new-password"
								<?php echo $conn_locked ? 'readonly style="background:#f0f0f1;"' : ''; ?>>
							<button type="button" class="button" id="cf7sb_key_toggle">表示</button>
							<button type="button" class="button" id="cf7sb_key_copy">コピー</button>
							<?php if ( $conn_locked ) : ?>
								<p class="description">誤設定防止のため閲覧のみです（セットアップコードの貼り付けでのみ変更できます）。</p>
							<?php else : ?>
								<p class="description">中央サーバーの秘密キー。空の場合、このサイトからは閲覧のみ（編集不可）になります。</p>
							<?php endif; ?>
						</td>
					</tr>
					<tr>
						<th scope="row"><label for="cf7sb_setup_code">セットアップコード</label></th>
						<td>
							<?php if ( '' !== $settings['url'] ) : ?>
								<input type="text" readonly id="cf7sb_setup_code_out" class="large-text code"
									value="<?php echo esc_attr( self::encode_setup_code( $settings['url'], $settings['key'] ) ); ?>"
									onclick="this.select();">
								<button type="button" class="button" id="cf7sb_code_copy" style="margin-top:4px;">このサイトの設定をコピー</button>
								<p class="description">2サイト目以降では、このコードを新しいサイトの「セットアップコード」欄に貼り付けて保存するだけで、URLと秘密キーが一括設定されます。</p>
							<?php endif; ?>
							<input type="text" id="cf7sb_setup_code" name="cf7sb_setup_code" class="large-text code"
								placeholder="別のサイトでコピーしたコードをここに貼り付けて「接続設定を保存」" autocomplete="off"
								<?php echo ( '' !== $settings['url'] ) ? 'style="margin-top:8px;"' : ''; ?>>
						</td>
					</tr>
				</table>
				<?php submit_button( '接続設定を保存' ); ?>
			</form>
			<?php endif; ?>

			<?php if ( 'blocklist' === $tab ) : ?>
			<p>
				最終取得: <strong><?php echo esc_html( $fetched_at ); ?></strong>
				（拒否ドメイン <?php echo count( $list['domains'] ); ?> 件 / 拒否メールアドレス <?php echo count( $list['emails'] ); ?> 件 / 拒否文字列 <?php echo count( $list['keywords'] ); ?> 件 / 拒否パターン <?php echo count( $list['patterns'] ); ?> 件）
				<?php if ( $fetch_error ) : ?>
					<span style="color:#b32d2e;">取得エラー: <?php echo esc_html( $fetch_error ); ?>（前回取得分で動作中）</span>
				<?php endif; ?>
			</p>

			<?php if ( $fetch_error && $settings['url'] && ! CF7SB_Server::is_enabled() ) : ?>
				<div class="notice notice-warning inline" style="max-width:800px;">
					<p>
						中央サーバー（<code><?php echo esc_html( wp_parse_url( $settings['url'], PHP_URL_HOST ) ); ?></code>）側の問題の可能性があります。
						このサイトは別サーバーのため自動修復できません。<strong>中央サーバーと同じサイトの管理画面</strong>を開いて問題を解消してから、このタブを開き直してください。
					</p>
				</div>
			<?php endif; ?>

			<?php if ( $has_pending ) : ?>
				<div class="notice notice-warning inline"><p><span class="dashicons dashicons-warning" style="color:#dba617; vertical-align:text-bottom;"></span> <strong>下の入力内容はまだ保存されていません。</strong>直前の保存が失敗したため、入力を復元して表示しています。上のエラーの原因を解消してから、もう一度「ブロックリストを保存」を押してください。</p></div>
			<?php endif; ?>

			<?php if ( ! $can_edit ) : ?>
				<div class="notice notice-info inline"><p>書き込み用秘密キーが未設定のため、このサイトからは編集できません（自動取得は動作します）。</p></div>
			<?php endif; ?>

			<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" id="cf7sb_blocklist_form" data-pending="<?php echo $has_pending ? '1' : '0'; ?>">
				<?php wp_nonce_field( 'cf7sb_save_blocklist' ); ?>
				<input type="hidden" name="action" value="cf7sb_save_blocklist">
				<table class="form-table" role="presentation">
					<tr>
						<th scope="row"><label for="cf7sb_block_message">ブロック時のメッセージ（全サイト共通）</label></th>
						<td>
							<input type="text" id="cf7sb_block_message" name="cf7sb_block_message" class="large-text"
								value="<?php echo esc_attr( $message_text ); ?>" <?php disabled( ! $can_edit ); ?>>
							<p class="description">ブロック時にフォーム全体の送信結果として表示する文言。リストと同じく中央サーバーに保存され、<strong>どのサイトで変更しても全サイトに反映</strong>されます。</p>
						</td>
					</tr>
					<tr>
						<th scope="row"><label for="cf7sb_domains">拒否ドメイン</label></th>
						<td>
							<textarea id="cf7sb_domains" name="cf7sb_domains" rows="8" class="large-text code cf7sb-taglist"
								data-cf7sb-label="拒否ドメイン" <?php disabled( ! $can_edit ); ?>><?php echo esc_textarea( $domains_text ); ?></textarea>
							<p class="description">メール欄はサブドメイン含む完全一致、本文・テキスト欄は文字列として含まれていればブロックします。例: <code>spam.com</code></p>
						</td>
					</tr>
					<tr>
						<th scope="row"><label for="cf7sb_emails">拒否メールアドレス</label></th>
						<td>
							<textarea id="cf7sb_emails" name="cf7sb_emails" rows="8" class="large-text code cf7sb-taglist"
								data-cf7sb-label="拒否メールアドレス" <?php disabled( ! $can_edit ); ?>><?php echo esc_textarea( $emails_text ); ?></textarea>
							<p class="description">メール欄がこのアドレスと完全一致した場合にブロックします。gmail.com などフリーメールの迷惑送信者は、ドメインではなくこちらに登録してください。例: <code>spam@gmail.com</code></p>
						</td>
					</tr>
					<tr>
						<th scope="row"><label for="cf7sb_keywords">拒否文字列</label></th>
						<td>
							<textarea id="cf7sb_keywords" name="cf7sb_keywords" rows="8" class="large-text code cf7sb-taglist"
								data-cf7sb-label="拒否文字列" <?php disabled( ! $can_edit ); ?>><?php echo esc_textarea( $keywords_text ); ?></textarea>
							<p class="description">本文・テキスト欄にこの文字列（会社名など）が含まれていればブロックします。</p>
						</td>
					</tr>
					<tr>
						<th scope="row">内蔵ルール</th>
						<td>
							<label>
								<input type="checkbox" name="cf7sb_block_uuid" value="1"
									<?php checked( $list['block_uuid'] ); ?> <?php disabled( ! $can_edit ); ?>>
								UUID形式の管理番号をブロックする（推奨・全サイト共通）
							</label>
							<p class="description">「管理番号: 08ffb4e6-9d35-4f9e-b173-…」のような <code>8桁-4桁-4桁-4桁-12桁</code> の英数字IDが本文などに含まれる送信を拒否します。この形式のIDが正当な問い合わせに現れることはまずありません。</p>
							<label style="display:block; margin-top:0.8em;">
								<input type="checkbox" name="cf7sb_block_link" value="1"
									<?php checked( $list['block_link'] ); ?> <?php disabled( ! $can_edit ); ?>>
								相互リンクフィルター（リンク設置依頼の営業メールをブロック・全サイト共通）
							</label>
							<p class="description">
								「相互リンク」等の依頼用語（+2点）に加え、リンク設置の言い回し・本文中のURL・「突然のご連絡」等の営業定型句・DRやSEO等の用語（各+1点）をスコア化し、<strong>合計3点以上</strong>の送信だけを拒否します。<br>
								キーワード単体では判定しないため、本文にたまたま「相互リンク」と書かれただけの正当な問い合わせ（URLや営業定型句がないもの）はブロックされません。
							</p>
						</td>
					</tr>
					<tr>
						<th scope="row"><label for="cf7sb_patterns">拒否パターン（正規表現）</label></th>
						<td>
							<textarea id="cf7sb_patterns" name="cf7sb_patterns" rows="6" class="large-text code cf7sb-taglist"
								data-cf7sb-label="拒否パターン（正規表現）" <?php disabled( ! $can_edit ); ?>><?php echo esc_textarea( $patterns_text ); ?></textarea>
							<p class="description">
								すべての入力欄（メール・電話・URL含む）に対して正規表現で判定します。デリミタ（<code>/～/</code>）は不要、大文字小文字は区別しません。<br>
								例（スペースを挟んだドメイン偽装）: <code>spam\s*\.\s*co\s*\.\s*jp</code>
							</p>
						</td>
					</tr>
				</table>
				<?php if ( $can_edit ) : ?>
					<?php submit_button( 'ブロックリストを保存（全サイトに反映）' ); ?>
				<?php endif; ?>
			</form>
			<?php endif; ?>

			<?php
			if ( 'log' === $tab ) :
				$log_data = CF7SB_Blocklist::fetch_logs( 100 );
			?>
				<p>
					中央サーバーに記録された、ブロックした送信の履歴です（プラグインを導入した<strong>全サイト共通</strong>・最新<?php echo (int) CF7SB_Server::MAX_LOGS; ?>件まで保持）。
				</p>

				<?php if ( ! empty( $log_data['error'] ) ) : ?>
					<div class="notice notice-error inline"><p>ログを取得できませんでした。（<?php echo esc_html( $log_data['error'] ); ?>）</p></div>
				<?php endif; ?>

				<?php if ( ! empty( $log_data['counts'] ) ) : ?>
					<h2 style="margin-bottom:0.4em;">理由別の内訳（記録済み <?php echo (int) $log_data['total']; ?> 件）</h2>
					<table class="widefat striped" style="max-width:520px; margin-bottom:1.5em;">
						<thead><tr><th>ブロック理由</th><th style="width:90px; text-align:right;">件数</th></tr></thead>
						<tbody>
							<?php foreach ( $log_data['counts'] as $rule => $count ) : ?>
								<tr>
									<td><?php echo esc_html( CF7SB_Blocklist::rule_label( $rule ) ); ?></td>
									<td style="text-align:right;"><?php echo (int) $count; ?></td>
								</tr>
							<?php endforeach; ?>
						</tbody>
					</table>
				<?php endif; ?>

				<h2 style="margin-bottom:0.4em;">履歴（最新<?php echo count( $log_data['logs'] ); ?>件）</h2>
				<table class="widefat striped">
					<thead>
						<tr>
							<th style="width:140px;">日時</th>
							<th style="width:130px;">サイト</th>
							<th style="width:160px;">ブロック理由</th>
							<th style="width:150px;">該当値</th>
							<th style="width:170px;">メールアドレス</th>
							<th>内容（抜粋）</th>
						</tr>
					</thead>
					<tbody>
						<?php if ( empty( $log_data['logs'] ) ) : ?>
							<tr><td colspan="6">まだブロックの記録はありません。</td></tr>
						<?php else : ?>
							<?php foreach ( $log_data['logs'] as $row ) : ?>
								<tr>
									<td><?php echo esc_html( wp_date( 'Y-m-d H:i', (int) $row['time'] ) ); ?></td>
									<td><?php echo esc_html( $row['site'] ); ?></td>
									<td><?php echo esc_html( CF7SB_Blocklist::rule_label( $row['rule'] ) ); ?></td>
									<td style="word-break:break-all;"><code><?php echo esc_html( $row['matched'] ); ?></code></td>
									<td style="word-break:break-all;"><?php echo esc_html( $row['email'] ); ?></td>
									<td style="word-break:break-all;">
										<?php echo esc_html( mb_substr( $row['excerpt'], 0, 120 ) ); ?><?php echo ( mb_strlen( $row['excerpt'] ) > 120 ) ? '…' : ''; ?>
										<span class="description" style="display:block;">
											項目: <?php echo esc_html( $row['field'] ); ?>
											<?php if ( ! empty( $row['form'] ) ) : ?> ／ フォーム: <?php echo esc_html( $row['form'] ); ?><?php endif; ?>
											<?php if ( ! empty( $row['ip'] ) ) : ?> ／ IP: <?php echo esc_html( $row['ip'] ); ?><?php endif; ?>
										</span>
									</td>
								</tr>
							<?php endforeach; ?>
						<?php endif; ?>
					</tbody>
				</table>

				<?php if ( ! empty( $log_data['logs'] ) ) : ?>
					<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" style="margin-top:1em;">
						<?php wp_nonce_field( 'cf7sb_clear_logs' ); ?>
						<input type="hidden" name="action" value="cf7sb_clear_logs">
						<button type="submit" class="button button-link-delete" onclick="return confirm('ブロックログをすべて消去しますか？（全サイト共通のログです）');">ログをすべて消去する</button>
					</form>
				<?php endif; ?>
			<?php endif; ?>
		</div>
		<style>
		.cf7sb-tags{display:flex;flex-wrap:wrap;gap:6px;align-items:center;max-width:640px;min-height:38px;
			padding:8px;border:1px solid #8c8f94;border-radius:4px;background:#fff;box-sizing:border-box;}
		.cf7sb-tag{display:inline-flex;align-items:center;gap:5px;background:#f0f0f1;border:1px solid #c3c4c7;
			border-radius:3px;padding:3px 8px;font-size:13px;font-family:Consolas,Monaco,monospace;word-break:break-all;}
		.cf7sb-tag-x{border:0;background:none;color:#787c82;cursor:pointer;padding:0 2px;font-size:16px;line-height:1;}
		.cf7sb-tag-x:hover{color:#d63638;}
		.cf7sb-tags-empty{color:#787c82;font-size:13px;}
		.cf7sb-tag-add{flex-shrink:0;}
		.cf7sb-modal-overlay{display:none;position:fixed;inset:0;background:rgba(0,0,0,.55);z-index:100100;}
		.cf7sb-modal-overlay.open{display:flex;align-items:flex-start;justify-content:center;padding-top:12vh;}
		.cf7sb-modal{background:#fff;border-radius:4px;box-shadow:0 3px 30px rgba(0,0,0,.3);
			padding:1.2em 1.5em 1.4em;width:540px;max-width:90vw;box-sizing:border-box;}
		.cf7sb-modal-title{margin:0 0 .3em;font-size:1.15em;}
		.cf7sb-modal-buttons{margin-top:.9em;text-align:right;}
		.cf7sb-modal-buttons .button{margin-left:6px;}
		</style>
		<script>
		( function () {
			function copyValue( input, button ) {
				input.focus();
				input.select();
				var done = function () {
					var label = button.textContent;
					button.textContent = 'コピーしました ✓';
					setTimeout( function () { button.textContent = label; }, 1500 );
				};
				if ( navigator.clipboard && navigator.clipboard.writeText ) {
					navigator.clipboard.writeText( input.value ).then( done );
				} else {
					document.execCommand( 'copy' );
					done();
				}
			}

			var key = document.getElementById( 'cf7sb_key' );
			var toggle = document.getElementById( 'cf7sb_key_toggle' );
			if ( key && toggle ) {
				toggle.addEventListener( 'click', function () {
					var hidden = ( 'password' === key.type );
					key.type = hidden ? 'text' : 'password';
					toggle.textContent = hidden ? '隠す' : '表示';
				} );
			}
			var keyCopy = document.getElementById( 'cf7sb_key_copy' );
			if ( key && keyCopy ) {
				keyCopy.addEventListener( 'click', function () { copyValue( key, keyCopy ); } );
			}
			var codeOut = document.getElementById( 'cf7sb_setup_code_out' );
			var codeCopy = document.getElementById( 'cf7sb_code_copy' );
			if ( codeOut && codeCopy ) {
				codeCopy.addEventListener( 'click', function () { copyValue( codeOut, codeCopy ); } );
			}

			// タグ入力UI: textareaを隠し、登録済み項目をタグで表示。追加はモーダル、削除は×ボタン。
			// 値の実体は元のtextareaに持たせたままなので、保存処理・入力復元はそのまま動く。
			var modalOverlay = null, modalTitle = null, modalInput = null, modalOnAdd = null;

			function splitLines( text ) {
				return text.split( /\r\n|\r|\n/ )
					.map( function ( s ) { return s.trim(); } )
					.filter( function ( s ) { return '' !== s; } );
			}

			function ensureModal() {
				if ( modalOverlay ) {
					return;
				}
				modalOverlay = document.createElement( 'div' );
				modalOverlay.className = 'cf7sb-modal-overlay';
				modalOverlay.innerHTML =
					'<div class="cf7sb-modal" role="dialog" aria-modal="true">' +
					'<h2 class="cf7sb-modal-title"></h2>' +
					'<p class="description">1行に1件ずつ入力してください（複数行まとめて貼り付けも可）。</p>' +
					'<textarea rows="5" class="large-text code cf7sb-modal-input"></textarea>' +
					'<div class="cf7sb-modal-buttons">' +
					'<button type="button" class="button cf7sb-modal-cancel">キャンセル</button>' +
					'<button type="button" class="button button-primary cf7sb-modal-add">追加する</button>' +
					'</div></div>';
				document.body.appendChild( modalOverlay );
				modalTitle = modalOverlay.querySelector( '.cf7sb-modal-title' );
				modalInput = modalOverlay.querySelector( '.cf7sb-modal-input' );

				var close = function () { modalOverlay.classList.remove( 'open' ); };
				modalOverlay.querySelector( '.cf7sb-modal-cancel' ).addEventListener( 'click', close );
				modalOverlay.addEventListener( 'click', function ( e ) {
					if ( e.target === modalOverlay ) { close(); }
				} );
				document.addEventListener( 'keydown', function ( e ) {
					if ( 'Escape' === e.key && modalOverlay.classList.contains( 'open' ) ) { close(); }
				} );
				modalOverlay.querySelector( '.cf7sb-modal-add' ).addEventListener( 'click', function () {
					var lines = splitLines( modalInput.value );
					if ( lines.length && modalOnAdd ) {
						modalOnAdd( lines );
					}
					close();
				} );
			}

			function openModal( label, onAdd ) {
				ensureModal();
				modalOnAdd = onAdd;
				modalTitle.textContent = label + ' を追加';
				modalInput.value = '';
				modalOverlay.classList.add( 'open' );
				modalInput.focus();
			}

			function initTagList( source ) {
				var editable = ! source.disabled;
				var label = source.getAttribute( 'data-cf7sb-label' ) || '';
				var wrap = document.createElement( 'div' );
				wrap.className = 'cf7sb-tags';
				source.parentNode.insertBefore( wrap, source );
				source.style.display = 'none';

				var values = function () { return splitLines( source.value ); };
				var sync = function ( list ) {
					source.value = list.join( '\n' );
					// 変更検知（保存ボタンの活性化）を通常入力と同じ経路で発火させる
					source.dispatchEvent( new Event( 'input', { bubbles: true } ) );
					rebuild();
				};
				var rebuild = function () {
					wrap.innerHTML = '';
					var list = values();
					list.forEach( function ( value, index ) {
						var tag = document.createElement( 'span' );
						tag.className = 'cf7sb-tag';
						var text = document.createElement( 'span' );
						text.textContent = value;
						tag.appendChild( text );
						if ( editable ) {
							var del = document.createElement( 'button' );
							del.type = 'button';
							del.className = 'cf7sb-tag-x';
							del.setAttribute( 'aria-label', '「' + value + '」を削除' );
							del.textContent = '×';
							del.addEventListener( 'click', function () {
								var current = values();
								current.splice( index, 1 );
								sync( current );
							} );
							tag.appendChild( del );
						}
						wrap.appendChild( tag );
					} );
					if ( ! list.length ) {
						var empty = document.createElement( 'span' );
						empty.className = 'cf7sb-tags-empty';
						empty.textContent = '登録なし';
						wrap.appendChild( empty );
					}
					if ( editable ) {
						var add = document.createElement( 'button' );
						add.type = 'button';
						add.className = 'button cf7sb-tag-add';
						add.textContent = '＋ 追加する';
						add.addEventListener( 'click', function () {
							openModal( label, function ( lines ) {
								var current = values();
								lines.forEach( function ( value ) {
									if ( -1 === current.indexOf( value ) ) {
										current.push( value );
									}
								} );
								sync( current );
							} );
						} );
						wrap.appendChild( add );
					}
				};
				rebuild();
			}

			document.querySelectorAll( 'textarea.cf7sb-taglist' ).forEach( initTagList );

			// ブロック設定: 変更がない間は保存ボタンを押せなくする
			var blForm = document.getElementById( 'cf7sb_blocklist_form' );
			if ( blForm ) {
				var saveBtn = blForm.querySelector( 'input[type="submit"], button[type="submit"]' );
				if ( saveBtn ) {
					var snapshot = function () {
						var parts = [];
						blForm.querySelectorAll( 'input, textarea' ).forEach( function ( el ) {
							if ( 'hidden' === el.type || 'submit' === el.type ) {
								return;
							}
							parts.push( el.name + '=' + ( 'checkbox' === el.type ? el.checked : el.value ) );
						} );
						return parts.join( '\n' );
					};
					var baseline = snapshot();
					var pending  = '1' === blForm.getAttribute( 'data-pending' ); // 未保存の復元入力があるときは最初から押せる
					var update = function () {
						saveBtn.disabled = ! pending && snapshot() === baseline;
					};
					blForm.addEventListener( 'input', update );
					blForm.addEventListener( 'change', update );
					update();
				}
			}
		} )();
		</script>
		<?php
	}
}
