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
			'message' => '送信できない内容が含まれています。',
		);
		return wp_parse_args( (array) get_option( self::OPTION_SETTINGS, array() ), $defaults );
	}

	public static function get_setting( $name ) {
		$settings = self::get_settings();
		return isset( $settings[ $name ] ) ? $settings[ $name ] : '';
	}

	/**
	 * 検証に使うリストを返す。キャッシュ（option）優先、未取得ならその場で取得を試みる。
	 *
	 * @return array{domains: string[], keywords: string[]}
	 */
	public static function get() {
		$stored = get_option( self::OPTION_LIST, array() );

		if ( empty( $stored['fetched_at'] ) && self::get_setting( 'url' ) ) {
			self::refresh();
			$stored = get_option( self::OPTION_LIST, array() );
		}

		return array(
			'domains'  => isset( $stored['domains'] ) ? (array) $stored['domains'] : array(),
			'emails'   => isset( $stored['emails'] ) ? (array) $stored['emails'] : array(),
			'keywords' => isset( $stored['keywords'] ) ? (array) $stored['keywords'] : array(),
		);
	}

	/**
	 * APIのURLがこのサイト自身と同じサーバーを指す場合、blocklist-api.php のファイルパスを返す。
	 * 同一サーバーではHTTPを介さず直接ファイルを読み書きすることで、
	 * ホスティングのレートリミット（HTTP 429）を回避しつつ高速化する。
	 *
	 * @return string|null
	 */
	private static function local_api_file() {
		$url = self::get_setting( 'url' );
		if ( ! $url ) {
			return null;
		}
		$api  = wp_parse_url( $url );
		$site = wp_parse_url( home_url() );
		if ( empty( $api['host'] ) || empty( $site['host'] )
			|| strtolower( $api['host'] ) !== strtolower( $site['host'] ) ) {
			return null;
		}
		$api_port  = isset( $api['port'] ) ? (int) $api['port'] : null;
		$site_port = isset( $site['port'] ) ? (int) $site['port'] : null;
		if ( $api_port !== $site_port ) {
			return null;
		}
		if ( empty( $_SERVER['DOCUMENT_ROOT'] ) || empty( $api['path'] ) ) {
			return null;
		}
		$file = realpath( rtrim( wp_unslash( $_SERVER['DOCUMENT_ROOT'] ), '/' ) . $api['path'] );
		return ( $file && is_file( $file ) ) ? $file : null;
	}

	/**
	 * URLの ?list= からリスト名を取り出す（サーバー側と同じルール）。
	 */
	private static function list_name() {
		$query = wp_parse_url( self::get_setting( 'url' ), PHP_URL_QUERY );
		$args  = array();
		if ( $query ) {
			parse_str( $query, $args );
		}
		$list = isset( $args['list'] ) && is_string( $args['list'] ) ? $args['list'] : 'default';
		return preg_match( '/^[a-zA-Z0-9_-]{1,50}$/', $list ) ? $list : 'default';
	}

	private static function store_lists( $domains, $keywords, $emails = array() ) {
		$stored               = get_option( self::OPTION_LIST, array() );
		$stored['domains']    = self::sanitize_lines( $domains );
		$stored['emails']     = self::sanitize_lines( $emails );
		$stored['keywords']   = self::sanitize_lines( $keywords );
		$stored['fetched_at'] = time();
		$stored['error']      = '';
		update_option( self::OPTION_LIST, $stored, false );
	}

	private static function store_error( $error ) {
		$stored          = get_option( self::OPTION_LIST, array() );
		$stored['error'] = $error;
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

		// 同一サーバーならファイルを直接読む
		$local = self::local_api_file();
		if ( $local ) {
			$json_file = dirname( $local ) . '/lists/' . self::list_name() . '.json';
			if ( ! is_file( $json_file ) ) {
				self::store_lists( array(), array() ); // まだ一度も保存されていないリスト
				return true;
			}
			$data = json_decode( (string) file_get_contents( $json_file ), true );
			if ( ! is_array( $data ) ) {
				return self::store_error( 'リストファイルの読み取りに失敗しました。' );
			}
			self::store_lists(
				isset( $data['domains'] ) ? $data['domains'] : array(),
				isset( $data['keywords'] ) ? $data['keywords'] : array(),
				isset( $data['emails'] ) ? $data['emails'] : array()
			);
			return true;
		}

		$response = wp_remote_get( $url, array( 'timeout' => 10 ) );

		if ( is_wp_error( $response ) ) {
			return self::store_error( $response->get_error_message() );
		}
		if ( 200 !== wp_remote_retrieve_response_code( $response ) ) {
			return self::store_error( 'HTTP ' . wp_remote_retrieve_response_code( $response ) );
		}
		$data = json_decode( wp_remote_retrieve_body( $response ), true );
		if ( ! is_array( $data ) ) {
			return self::store_error( 'JSONの解析に失敗しました。' );
		}

		self::store_lists(
			isset( $data['domains'] ) ? $data['domains'] : array(),
			isset( $data['keywords'] ) ? $data['keywords'] : array(),
			isset( $data['emails'] ) ? $data['emails'] : array()
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
	public static function push( $domains, $keywords, $emails = array() ) {
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

		// 同一サーバーならファイルを直接書く
		$local = self::local_api_file();
		if ( $local ) {
			// サーバーファイル内のキーと照合（HTTP経由と同じ認可チェック）
			$contents = (string) file_get_contents( $local );
			if ( ! preg_match( "/const CF7SB_API_KEY = '([^']*)';/", $contents, $m ) || ! hash_equals( $m[1], $key ) ) {
				return new WP_Error( 'cf7sb_push_failed', '秘密キーが一致しません。' );
			}

			$dir = dirname( $local ) . '/lists';
			if ( ! is_dir( $dir ) && ! mkdir( $dir, 0755, true ) ) {
				return new WP_Error( 'cf7sb_push_failed', '保存先ディレクトリを作成できません。' );
			}
			$payload = array(
				'domains'  => $clean_domains,
				'emails'   => $clean_emails,
				'keywords' => $clean_keywords,
				'updated'  => date( 'c' ),
			);
			$json = wp_json_encode( $payload, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT );
			if ( false === file_put_contents( $dir . '/' . self::list_name() . '.json', $json, LOCK_EX ) ) {
				return new WP_Error( 'cf7sb_push_failed', 'ファイルの書き込みに失敗しました。' );
			}

			self::store_lists( $clean_domains, $clean_keywords, $clean_emails );
			return true;
		}

		$body = wp_json_encode( array(
			'domains'  => $clean_domains,
			'emails'   => $clean_emails,
			'keywords' => $clean_keywords,
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
			$msg    = isset( $detail['error'] ) ? $detail['error'] : 'HTTP ' . $code;
			return new WP_Error( 'cf7sb_push_failed', $msg );
		}

		// サーバーが保存済みデータを返すので、再取得せずそのままキャッシュに反映（リクエスト数削減）
		$saved = json_decode( wp_remote_retrieve_body( $response ), true );
		if ( is_array( $saved ) && isset( $saved['domains'] ) ) {
			self::store_lists(
				$saved['domains'],
				isset( $saved['keywords'] ) ? $saved['keywords'] : array(),
				isset( $saved['emails'] ) ? $saved['emails'] : array()
			);
		} else {
			self::store_lists( $clean_domains, $clean_keywords, $clean_emails );
		}
		return true;
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
