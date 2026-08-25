<?php
/**
 * 中央サーバーからブロックリストを取得・キャッシュし、書き戻しも行う。
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class CF7SB_Blocklist {

	const OPTION_SETTINGS = 'cf7sb_settings';
	const OPTION_LIST     = 'cf7sb_blocklist';
	const CRON_HOOK       = 'cf7sb_refresh_blocklist';

	public static function init() {
		add_action( self::CRON_HOOK, array( __CLASS__, 'refresh' ) );

		// 有効化以外の経路（手動アップロード上書き等）でもcronが消えないよう保険
		if ( ! wp_next_scheduled( self::CRON_HOOK ) && self::get_setting( 'url' ) ) {
			wp_schedule_event( time() + MINUTE_IN_SECONDS, 'hourly', self::CRON_HOOK );
		}
	}

	public static function activate() {
		if ( ! wp_next_scheduled( self::CRON_HOOK ) ) {
			wp_schedule_event( time() + MINUTE_IN_SECONDS, 'hourly', self::CRON_HOOK );
		}
	}

	public static function deactivate() {
		wp_clear_scheduled_hook( self::CRON_HOOK );
	}

	public static function get_settings() {
		$defaults = array(
			'url'     => '',
			'key'     => '',
			'message' => '迷惑行為と判定されたため送信を拒否しました。',
		);
		return wp_parse_args( (array) get_option( self::OPTION_SETTINGS, array() ), $defaults );
	}

	public static function get_setting( $name ) {
		$settings = self::get_settings();
		return isset( $settings[ $name ] ) ? $settings[ $name ] : '';
	}

	/** 取得済みリストをこの秒数まで新鮮とみなす（超えたら次の判定時に自動再取得） */
	const FRESH_TTL = 60;

	/** このリクエスト内で鮮度確認を済ませたか */
	private static $freshness_checked = false;

	/**
	 * 検証に使うリストを返す。
	 * どこかのサイトでリストが変更されてもすぐ反映されるよう、TTLを超えていたら
	 * その場で中央サーバーから再取得する（TTL内・取得失敗時はキャッシュで動作）。
	 *
	 * @return array{domains: string[], keywords: string[]}
	 */
	public static function get() {
		$stored = get_option( self::OPTION_LIST, array() );

		if ( ! self::$freshness_checked && self::get_setting( 'url' ) ) {
			self::$freshness_checked = true;
			$checked_at = ! empty( $stored['checked_at'] )
				? (int) $stored['checked_at']
				: ( ! empty( $stored['fetched_at'] ) ? (int) $stored['fetched_at'] : 0 );
			if ( time() - $checked_at > self::FRESH_TTL ) {
				self::refresh();
				$stored = get_option( self::OPTION_LIST, array() );
			}
		}

		return array(
			'domains'    => isset( $stored['domains'] ) ? (array) $stored['domains'] : array(),
			'emails'     => isset( $stored['emails'] ) ? (array) $stored['emails'] : array(),
			'keywords'   => isset( $stored['keywords'] ) ? (array) $stored['keywords'] : array(),
			'patterns'   => isset( $stored['patterns'] ) ? (array) $stored['patterns'] : array(),
			'message'    => isset( $stored['message'] ) ? (string) $stored['message'] : '',
			'block_uuid' => isset( $stored['block_uuid'] ) ? (bool) $stored['block_uuid'] : true,
			'block_link' => isset( $stored['block_link'] ) ? (bool) $stored['block_link'] : false,
		);
	}

	/** 内蔵ルール: UUID形式（迷惑メールの「管理番号」等）の正規表現 */
	const UUID_PATTERN = '\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b';

	/**
	 * ブロック時に表示するメッセージ（全サイト共通）。
	 * 中央リストに設定があればそれを使い、なければ旧・サイト個別設定→既定文言の順で使う。
	 */
	public static function get_message() {
		$stored = get_option( self::OPTION_LIST, array() );
		if ( ! empty( $stored['message'] ) ) {
			return (string) $stored['message'];
		}
		return self::get_setting( 'message' );
	}

	private static function store_lists( $domains, $keywords, $emails = array(), $message = '', $patterns = array(), $block_uuid = true, $block_link = false ) {
		$stored               = get_option( self::OPTION_LIST, array() );
		$stored['domains']    = self::sanitize_lines( $domains );
		$stored['emails']     = self::sanitize_lines( $emails );
		$stored['keywords']   = self::sanitize_lines( $keywords );
		$stored['patterns']   = self::sanitize_patterns( $patterns );
		$stored['message']    = trim( wp_strip_all_tags( (string) $message ) );
		$stored['block_uuid'] = (bool) $block_uuid;
		$stored['block_link'] = (bool) $block_link;
		$stored['fetched_at'] = time();
		$stored['checked_at'] = time();
		$stored['error']      = '';
		update_option( self::OPTION_LIST, $stored, false );
	}

	/**
	 * 正規表現パターンの配列を正規化する（trim・空行除去・重複除去・コンパイル不能なものを除外）。
	 * デリミタは付けずに保存し、使用時に #...#iu で包む。
	 */
	public static function sanitize_patterns( $items ) {
		$out = array();
		foreach ( (array) $items as $item ) {
			if ( ! is_string( $item ) ) {
				continue;
			}
			$item = trim( $item );
			if ( '' === $item || mb_strlen( $item ) > 500 ) {
				continue;
			}
			if ( false === @preg_match( self::wrap_pattern( $item ), '' ) ) {
				continue; // 正規表現として不正なものは除外
			}
			$out[] = $item;
		}
		return array_values( array_unique( $out ) );
	}

	/**
	 * 保存用パターンを実行可能な正規表現にする。
	 */
	public static function wrap_pattern( $pattern ) {
		return '#' . str_replace( '#', '\#', (string) $pattern ) . '#iu';
	}

	private static function store_error( $error ) {
		$stored               = get_option( self::OPTION_LIST, array() );
		$stored['error']      = $error;
		$stored['checked_at'] = time(); // 失敗時もTTLの間は再試行しない（送信を遅くしないため）
		update_option( self::OPTION_LIST, $stored, false );
		return new WP_Error( 'cf7sb_fetch_failed', $error );
	}

	/**
	 * 中央サーバーから再取得。失敗時は前回のリストを保持したままエラーだけ記録する。
	 *
	 * @return true|WP_Error
	 */
	public static function refresh() {
		$url = self::get_setting( 'url' );
		if ( ! $url ) {
			return new WP_Error( 'cf7sb_no_url', 'ブロックリストURLが設定されていません。' );
		}

		// このサイト自身が中央サーバー（かんたんセットアップ方式）なら直接読む
		$server_list = CF7SB_Server::local_list_name( $url );
		if ( null !== $server_list ) {
			$data = CF7SB_Server::get_list( $server_list );
			self::store_lists( $data['domains'], $data['keywords'], $data['emails'], $data['message'], $data['patterns'], $data['block_uuid'], $data['block_link'] );
			return true;
		}

		$response = wp_remote_get( $url, array( 'timeout' => 10 ) );

		if ( is_wp_error( $response ) ) {
			return self::store_error( $response->get_error_message() );
		}
		$code = wp_remote_retrieve_response_code( $response );
		if ( 200 !== $code ) {
			// サーバーがエラー内容を返していれば、そのまま伝える（原因の特定を容易にするため）
			$detail = json_decode( wp_remote_retrieve_body( $response ), true );
			$reason = '';
			if ( is_array( $detail ) ) {
				$reason = ! empty( $detail['error'] ) ? $detail['error'] : ( ! empty( $detail['message'] ) ? $detail['message'] : '' );
			}
			return self::store_error( $reason ? $reason . '（HTTP ' . $code . '）' : 'HTTP ' . $code );
		}
		$data = json_decode( wp_remote_retrieve_body( $response ), true );
		if ( ! is_array( $data ) ) {
			return self::store_error( 'JSONの解析に失敗しました。' );
		}

		self::store_lists(
			isset( $data['domains'] ) ? $data['domains'] : array(),
			isset( $data['keywords'] ) ? $data['keywords'] : array(),
			isset( $data['emails'] ) ? $data['emails'] : array(),
			isset( $data['message'] ) ? $data['message'] : '',
			isset( $data['patterns'] ) ? $data['patterns'] : array(),
			isset( $data['block_uuid'] ) ? (bool) $data['block_uuid'] : true,
			isset( $data['block_link'] ) ? (bool) $data['block_link'] : false
		);
		return true;
	}

	/**
	 * 編集内容を中央サーバーへ書き戻す。成功したらローカルキャッシュも更新。
	 *
	 * @param string[] $domains
	 * @param string[] $keywords
	 * @return true|WP_Error
	 */
	public static function push( $domains, $keywords, $emails = array(), $message = '', $patterns = array(), $block_uuid = true, $block_link = false ) {
		$block_uuid = (bool) $block_uuid;
		$block_link = (bool) $block_link;
		$url = self::get_setting( 'url' );
		$key = self::get_setting( 'key' );

		if ( ! $url ) {
			return new WP_Error( 'cf7sb_no_url', 'ブロックリストURLが設定されていません。' );
		}
		if ( ! $key ) {
			return new WP_Error( 'cf7sb_no_key', '書き込み用秘密キーが設定されていないため、編集内容を保存できません。' );
		}

		$clean_domains  = self::sanitize_lines( $domains );
		$clean_keywords = self::sanitize_lines( $keywords );
		$clean_emails   = self::sanitize_lines( $emails );
		$clean_message  = trim( wp_strip_all_tags( (string) $message ) );
		$clean_patterns = self::sanitize_patterns( $patterns );

		// このサイト自身が中央サーバー（かんたんセットアップ方式）なら直接書く
		$server_list = CF7SB_Server::local_list_name( $url );
		if ( null !== $server_list ) {
			if ( ! hash_equals( CF7SB_Server::get_key(), $key ) ) {
				return new WP_Error( 'cf7sb_push_failed', '秘密キーが一致しません。' );
			}
			$saved = CF7SB_Server::save_list( $server_list, array(
				'domains'    => $clean_domains,
				'emails'     => $clean_emails,
				'keywords'   => $clean_keywords,
				'patterns'   => $clean_patterns,
				'block_uuid' => $block_uuid,
			'block_link' => $block_link,
				'block_link' => $block_link,
				'message'    => $clean_message,
			) );
			self::store_lists( $saved['domains'], $saved['keywords'], $saved['emails'], $saved['message'], $saved['patterns'], isset( $saved['block_uuid'] ) ? (bool) $saved['block_uuid'] : true, isset( $saved['block_link'] ) ? (bool) $saved['block_link'] : false );
			return true;
		}

		$body = wp_json_encode( array(
			'domains'  => $clean_domains,
			'emails'   => $clean_emails,
			'keywords' => $clean_keywords,
			'patterns' => $clean_patterns,
			'block_uuid' => $block_uuid,
			'block_link' => $block_link,
			'message'  => $clean_message,
		) );

		$response = wp_remote_post( $url, array(
			'timeout' => 10,
			'headers' => array(
				'Content-Type' => 'application/json; charset=utf-8',
				'X-CF7SB-Key'  => $key,
			),
			'body'    => $body,
		) );

		if ( is_wp_error( $response ) ) {
			return $response;
		}

		$code = wp_remote_retrieve_response_code( $response );
		if ( 200 !== $code ) {
			$detail = json_decode( wp_remote_retrieve_body( $response ), true );
			$msg    = 'HTTP ' . $code;
			if ( is_array( $detail ) ) {
				$msg = ! empty( $detail['error'] ) ? $detail['error'] : ( ! empty( $detail['message'] ) ? $detail['message'] : $msg );
			}
			return new WP_Error( 'cf7sb_push_failed', $msg );
		}

		// サーバーが保存済みデータを返すので、再取得せずそのままキャッシュに反映（リクエスト数削減）
		$saved = json_decode( wp_remote_retrieve_body( $response ), true );
		if ( is_array( $saved ) && isset( $saved['domains'] ) ) {
			self::store_lists(
				$saved['domains'],
				isset( $saved['keywords'] ) ? $saved['keywords'] : array(),
				isset( $saved['emails'] ) ? $saved['emails'] : array(),
				isset( $saved['message'] ) ? $saved['message'] : $clean_message,
				isset( $saved['patterns'] ) ? $saved['patterns'] : $clean_patterns,
				isset( $saved['block_uuid'] ) ? (bool) $saved['block_uuid'] : $block_uuid,
				isset( $saved['block_link'] ) ? (bool) $saved['block_link'] : $block_link
			);
		} else {
			self::store_lists( $clean_domains, $clean_keywords, $clean_emails, $clean_message, $clean_patterns, $block_uuid, $block_link );
		}
		return true;
	}

	/**
	 * リスト配信URLから、同じ中央サーバーの別エンドポイントのURLを作る。
	 * （パス形式・rest_route形式のどちらにも対応）
	 */
	private static function endpoint_url( $url, $endpoint ) {
		return ( false !== strpos( $url, 'cf7sb/v1/list' ) )
			? str_replace( 'cf7sb/v1/list', 'cf7sb/v1/' . $endpoint, $url )
			: '';
	}

	/**
	 * ブロックした送信を中央サーバーのログに記録する（全サイトで共有）。
	 */
	public static function log_block( $entry ) {
		$url = self::get_setting( 'url' );
		$key = self::get_setting( 'key' );
		if ( ! $url || ! $key ) {
			return false;
		}

		$entry['time'] = time();
		$entry['site'] = get_bloginfo( 'name' );

		// このサイト自身が中央サーバーなら直接書く
		$server_list = CF7SB_Server::local_list_name( $url );
		if ( null !== $server_list ) {
			return CF7SB_Server::add_log( $server_list, $entry );
		}

		$log_url = self::endpoint_url( $url, 'log' );
		if ( ! $log_url ) {
			return false;
		}
		wp_remote_post( $log_url, array(
			'timeout' => 5,
			'headers' => array(
				'Content-Type' => 'application/json; charset=utf-8',
				'X-CF7SB-Key'  => $key,
			),
			'body'    => wp_json_encode( $entry ),
		) );
		return true;
	}

	/**
	 * 中央サーバーからブロックログを取得する。
	 *
	 * @return array{logs: array, total: int, counts: array, error: string}
	 */
	public static function fetch_logs( $limit = 100 ) {
		$empty = array( 'logs' => array(), 'total' => 0, 'counts' => array(), 'error' => '' );

		$url = self::get_setting( 'url' );
		$key = self::get_setting( 'key' );
		if ( ! $url ) {
			return array_merge( $empty, array( 'error' => 'ブロックリストURLが設定されていません。' ) );
		}

		$server_list = CF7SB_Server::local_list_name( $url );
		if ( null !== $server_list ) {
			return array_merge( $empty, CF7SB_Server::get_logs( $server_list, $limit ) );
		}

		if ( ! $key ) {
			return array_merge( $empty, array( 'error' => 'ログの閲覧には秘密キーが必要です。' ) );
		}
		$log_url = self::endpoint_url( $url, 'log' );
		if ( ! $log_url ) {
			return array_merge( $empty, array( 'error' => 'ログ用URLを組み立てられませんでした。' ) );
		}

		$response = wp_remote_get( add_query_arg( 'limit', (int) $limit, $log_url ), array(
			'timeout' => 10,
			'headers' => array( 'X-CF7SB-Key' => $key ),
		) );
		if ( is_wp_error( $response ) ) {
			return array_merge( $empty, array( 'error' => $response->get_error_message() ) );
		}
		$code = wp_remote_retrieve_response_code( $response );
		$data = json_decode( wp_remote_retrieve_body( $response ), true );
		if ( 200 !== $code || ! is_array( $data ) ) {
			$reason = ( is_array( $data ) && ! empty( $data['message'] ) ) ? $data['message'] : 'HTTP ' . $code;
			return array_merge( $empty, array( 'error' => $reason ) );
		}

		return array_merge( $empty, $data );
	}

	/**
	 * 中央サーバーのブロックログを消去する。
	 *
	 * @return true|WP_Error
	 */
	public static function clear_logs() {
		$url = self::get_setting( 'url' );
		$key = self::get_setting( 'key' );
		if ( ! $url || ! $key ) {
			return new WP_Error( 'cf7sb_no_key', 'ログの消去には接続設定と秘密キーが必要です。' );
		}

		$server_list = CF7SB_Server::local_list_name( $url );
		if ( null !== $server_list ) {
			CF7SB_Server::clear_logs( $server_list );
			return true;
		}

		$log_url = self::endpoint_url( $url, 'log' );
		if ( ! $log_url ) {
			return new WP_Error( 'cf7sb_no_url', 'ログ用URLを組み立てられませんでした。' );
		}
		$response = wp_remote_request( $log_url, array(
			'method'  => 'DELETE',
			'timeout' => 10,
			'headers' => array( 'X-CF7SB-Key' => $key ),
		) );
		if ( is_wp_error( $response ) ) {
			return $response;
		}
		if ( 200 !== wp_remote_retrieve_response_code( $response ) ) {
			$data = json_decode( wp_remote_retrieve_body( $response ), true );
			return new WP_Error( 'cf7sb_clear_failed', ( is_array( $data ) && ! empty( $data['message'] ) ) ? $data['message'] : 'ログを消去できませんでした。' );
		}
		return true;
	}

	/** ブロック理由の表示名 */
	public static function rule_label( $rule ) {
		$labels = array(
			'domain'  => '拒否ドメイン',
			'email'   => '拒否メールアドレス',
			'keyword' => '拒否文字列',
			'pattern' => '拒否パターン',
			'uuid'    => '内蔵: UUID管理番号',
			'link'    => '内蔵: 相互リンクフィルター',
		);
		return isset( $labels[ $rule ] ) ? $labels[ $rule ] : ( $rule ? $rule : '不明' );
	}

	/**
	 * 配列を「文字列のみ・trim済み・空行なし・重複なし」に正規化する。
	 */
	public static function sanitize_lines( $items ) {
		$out = array();
		foreach ( (array) $items as $item ) {
			if ( ! is_string( $item ) ) {
				continue;
			}
			$item = trim( wp_strip_all_tags( $item ) );
			if ( '' !== $item ) {
				$out[] = $item;
			}
		}
		return array_values( array_unique( $out ) );
	}
}
