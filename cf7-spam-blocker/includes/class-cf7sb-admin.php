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
		add_action( 'admin_post_cf7sb_download_server', array( __CLASS__, 'handle_download_server' ) );
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

		$mode = isset( $_POST['cf7sb_mode'] ) ? sanitize_key( wp_unslash( $_POST['cf7sb_mode'] ) ) : 'field';
		$settings['mode'] = in_array( $mode, array( 'field', 'stealth_error', 'fake_success' ), true ) ? $mode : 'field';

		// セットアップコードが貼り付けられていれば、URL・キーをコードから一括設定
		$code = sanitize_text_field( isset( $_POST['cf7sb_setup_code'] ) ? wp_unslash( $_POST['cf7sb_setup_code'] ) : '' );
		if ( '' !== $code ) {
			$decoded = self::decode_setup_code( $code );
			if ( null === $decoded ) {
				set_transient( 'cf7sb_last_error_' . get_current_user_id(), 'セットアップコードの形式が正しくありません。', MINUTE_IN_SECONDS );
				self::redirect_back( 'code_invalid' );
			}
			$settings['url'] = $decoded['url'];
			$settings['key'] = $decoded['key'];
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

		$domains_text  = isset( $_POST['cf7sb_domains'] ) ? (string) wp_unslash( $_POST['cf7sb_domains'] ) : '';
		$emails_text   = isset( $_POST['cf7sb_emails'] ) ? (string) wp_unslash( $_POST['cf7sb_emails'] ) : '';
		$keywords_text = isset( $_POST['cf7sb_keywords'] ) ? (string) wp_unslash( $_POST['cf7sb_keywords'] ) : '';

		$pushed = CF7SB_Blocklist::push(
			self::textarea_to_array( $domains_text ),
			self::textarea_to_array( $keywords_text ),
			self::textarea_to_array( $emails_text )
		);
		if ( is_wp_error( $pushed ) ) {
			set_transient( 'cf7sb_last_error_' . get_current_user_id(), $pushed->get_error_message(), MINUTE_IN_SECONDS );
			// 入力内容を消さないよう保持して、再表示時にフォームへ戻す
			set_transient(
				'cf7sb_pending_input_' . get_current_user_id(),
				array( 'domains' => $domains_text, 'emails' => $emails_text, 'keywords' => $keywords_text ),
				10 * MINUTE_IN_SECONDS
			);
			self::redirect_back( 'push_failed' );
		}

		delete_transient( 'cf7sb_pending_input_' . get_current_user_id() );
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

	/**
	 * サーバー設置用の blocklist-api.php を、秘密キーを埋め込んだ状態でダウンロードさせる。
	 * このサイトの秘密キーが未設定なら自動生成して設定にも保存する（再ダウンロードしても同じキー）。
	 */
	public static function handle_download_server() {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( '権限がありません。' );
		}
		check_admin_referer( 'cf7sb_download_server' );

		$settings = CF7SB_Blocklist::get_settings();
		if ( '' === $settings['key'] ) {
			$settings['key'] = 'cf7sb-' . bin2hex( random_bytes( 20 ) );
			update_option( CF7SB_Blocklist::OPTION_SETTINGS, $settings, false );
		}

		$template = file_get_contents( CF7SB_DIR . 'server/blocklist-api.tpl' );
		if ( false === $template ) {
			wp_die( 'テンプレートファイルが見つかりません。プラグインを再インストールしてください。' );
		}

		$file = preg_replace(
			"/const CF7SB_API_KEY = '[^']*';/",
			"const CF7SB_API_KEY = '" . $settings['key'] . "';",
			$template,
			1
		);

		nocache_headers();
		header( 'Content-Type: application/octet-stream' );
		header( 'Content-Disposition: attachment; filename="blocklist-api.php"' );
		header( 'Content-Length: ' . strlen( $file ) );
		echo $file; // phpcs:ignore WordPress.Security.EscapeOutput
		exit;
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
			'blocklist_saved' => array( 'success', 'ブロックリストを中央サーバーに保存しました。同じリストを参照する全サイトに反映されます（各サイトの次回取得時）。' ),
			'refreshed'       => array( 'success', 'ブロックリストを再取得しました。' ),
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
		if ( $has_pending ) {
			delete_transient( 'cf7sb_pending_input_' . get_current_user_id() );
			$domains_text  = isset( $pending['domains'] ) ? $pending['domains'] : $domains_text;
			$emails_text   = isset( $pending['emails'] ) ? $pending['emails'] : $emails_text;
			$keywords_text = isset( $pending['keywords'] ) ? $pending['keywords'] : $keywords_text;
		}
		?>
		<div class="wrap">
			<h1>CF7 Spam Blocker</h1>

			<details style="margin:1em 0; padding:0.2em 1.2em; background:#fff; border:1px solid #c3c4c7; border-radius:4px; max-width:800px;" <?php echo ( '' === $settings['url'] ) ? 'open' : ''; ?>>
				<summary style="cursor:pointer; font-weight:600; font-size:1.05em; padding:0.6em 0;">初期セットアップガイド</summary>
				<ol style="margin-top:0;">
					<li style="margin-bottom:1em;">
						<strong>サーバー設置ファイルをダウンロード</strong><br>
						ブロックリストを保管する <code>blocklist-api.php</code> を、秘密キー設定済みの状態でダウンロードします（ファイルの編集は不要です）。
						<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" style="margin:0.5em 0;">
							<?php wp_nonce_field( 'cf7sb_download_server' ); ?>
							<input type="hidden" name="action" value="cf7sb_download_server">
							<button type="submit" class="button button-primary">サーバー設置ファイルをダウンロード</button>
						</form>
						<p class="description">このサイトの「書き込み用秘密キー」が未設定の場合は、安全なキーを自動生成して下の設定欄にも保存します（画面を再読み込みすると表示されます）。</p>
					</li>
					<li style="margin-bottom:1em;">
						<strong>サーバーにアップロード</strong><br>
						FTPなどで、管理しているサーバーの任意の場所に設置します（例: <code>https://example.com/cf7sb/blocklist-api.php</code>）。設置は全サイト共通で<strong>1回だけ</strong>です。
					</li>
					<li style="margin-bottom:1em;">
						<strong>接続設定を保存</strong><br>
						設置先のURLを下の「ブロックリストURL」に入力して「接続設定を保存」。保存後に「最終取得」の日時が表示されれば接続成功です。<code>?list=会社A</code> のようにリスト名を付けると、用途別に別のリストを共有できます。
					</li>
					<li style="margin-bottom:1em;">
						<strong>ブロック条件を登録</strong><br>
						下の「ブロックリスト」で拒否ドメイン・拒否メールアドレス・拒否文字列を1行1件で入力して保存します。
					</li>
					<li style="margin-bottom:1em;">
						<strong>2サイト目以降</strong><br>
						ファイル設置は不要です。設定済みサイトの「セットアップコード」をコピーし、新しいサイトの同じ欄に貼り付けて保存するだけで、URLと秘密キーが一括設定され同じリストが共有されます。
					</li>
				</ol>
				<p style="margin-bottom:1em;">動作確認: Contact Form 7 のフォームのメール欄に拒否ドメインのアドレスを入力して送信し、「<?php echo esc_html( $settings['message'] ); ?>」と表示されればOKです。</p>
			</details>

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
							<button type="button" class="button" id="cf7sb_key_toggle">表示</button>
							<button type="button" class="button" id="cf7sb_key_copy">コピー</button>
							<p class="description">blocklist-api.php に設定したキー。空の場合、このサイトからは閲覧のみ（編集不可）になります。</p>
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
					<tr>
						<th scope="row">ブロック時の動作</th>
						<td>
							<fieldset>
								<label style="display:block; margin-bottom:0.6em;">
									<input type="radio" name="cf7sb_mode" value="field" <?php checked( $settings['mode'], 'field' ); ?>>
									<strong>該当欄にエラーを表示</strong>
									<p class="description" style="margin:0.2em 0 0 1.6em;">下の「エラーメッセージ」を該当フィールドの下に表示します。原因の欄が相手に分かります。</p>
								</label>
								<label style="display:block; margin-bottom:0.6em;">
									<input type="radio" name="cf7sb_mode" value="stealth_error" <?php checked( $settings['mode'], 'stealth_error' ); ?>>
									<strong>原因を伏せた送信エラーにする</strong>
									<p class="description" style="margin:0.2em 0 0 1.6em;">どの欄が原因かは示さず、「メッセージの送信に失敗しました。後でまたお試しください。」というサーバー障害風の表示になります（文言はCF7の「メッセージ」設定の「送信失敗」に従います）。</p>
								</label>
								<label style="display:block;">
									<input type="radio" name="cf7sb_mode" value="fake_success" <?php checked( $settings['mode'], 'fake_success' ); ?>>
									<strong>送信成功に見せかける（実際には送信しない）</strong>
									<p class="description" style="margin:0.2em 0 0 1.6em;">通常の送信完了メッセージを表示しますが、メールは送信されません。相手はブロックに気づけません。⚠ 誤ってブロックされた正規の問い合わせも「成功」に見えるため、リストの内容は慎重に管理してください。</p>
								</label>
							</fieldset>
						</td>
					</tr>
					<tr>
						<th scope="row"><label for="cf7sb_message">ブロック時のエラーメッセージ</label></th>
						<td>
							<input type="text" id="cf7sb_message" name="cf7sb_message" class="regular-text"
								value="<?php echo esc_attr( $settings['message'] ); ?>">
							<p class="description">「該当欄にエラーを表示」モードのときに使われます。</p>
						</td>
					</tr>
				</table>
				<?php submit_button( '接続設定を保存' ); ?>
			</form>

			<hr>

			<h2>ブロックリスト</h2>
			<p>
				最終取得: <strong><?php echo esc_html( $fetched_at ); ?></strong>
				（拒否ドメイン <?php echo count( $list['domains'] ); ?> 件 / 拒否メールアドレス <?php echo count( $list['emails'] ); ?> 件 / 拒否文字列 <?php echo count( $list['keywords'] ); ?> 件）
				<?php if ( $fetch_error ) : ?>
					<span style="color:#b32d2e;">取得エラー: <?php echo esc_html( $fetch_error ); ?>（前回取得分で動作中）</span>
				<?php endif; ?>
			</p>

			<?php if ( $has_pending ) : ?>
				<div class="notice notice-warning inline"><p><strong>⚠ 下の入力内容はまだ保存されていません。</strong>直前の保存が失敗したため、入力を復元して表示しています。上のエラーの原因を解消してから、もう一度「ブロックリストを保存」を押してください。</p></div>
			<?php endif; ?>

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
								<?php disabled( ! $can_edit ); ?>><?php echo esc_textarea( $domains_text ); ?></textarea>
							<p class="description">メール欄はサブドメイン含む完全一致、本文・テキスト欄は文字列として含まれていればブロックします。例: <code>spam.com</code></p>
						</td>
					</tr>
					<tr>
						<th scope="row"><label for="cf7sb_emails">拒否メールアドレス（1行1件）</label></th>
						<td>
							<textarea id="cf7sb_emails" name="cf7sb_emails" rows="8" class="large-text code"
								<?php disabled( ! $can_edit ); ?>><?php echo esc_textarea( $emails_text ); ?></textarea>
							<p class="description">メール欄がこのアドレスと完全一致した場合にブロックします。gmail.com などフリーメールの迷惑送信者は、ドメインではなくこちらに登録してください。例: <code>spam@gmail.com</code></p>
						</td>
					</tr>
					<tr>
						<th scope="row"><label for="cf7sb_keywords">拒否文字列（1行1件）</label></th>
						<td>
							<textarea id="cf7sb_keywords" name="cf7sb_keywords" rows="8" class="large-text code"
								<?php disabled( ! $can_edit ); ?>><?php echo esc_textarea( $keywords_text ); ?></textarea>
							<p class="description">本文・テキスト欄にこの文字列（会社名など）が含まれていればブロックします。</p>
						</td>
					</tr>
				</table>
				<?php if ( $can_edit ) : ?>
					<?php submit_button( 'ブロックリストを保存（全サイトに反映）' ); ?>
				<?php endif; ?>
			</form>
		</div>
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
		} )();
		</script>
		<?php
	}
}
