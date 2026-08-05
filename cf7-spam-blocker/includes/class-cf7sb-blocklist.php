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
			'keywords' => isset( $stored['keywords'] ) ? (array) $stored['keywords'] : array(),
		);
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

		$response = wp_remote_get( $url, array( 'timeout' => 10 ) );
		$error    = null;

		if ( is_wp_error( $response ) ) {
			$error = $response->get_error_message();
		} elseif ( 200 !== wp_remote_retrieve_response_code( $response ) ) {
			$error = 'HTTP ' . wp_remote_retrieve_response_code( $response );
		} else {
			$data = json_decode( wp_remote_retrieve_body( $response ), true );
			if ( ! is_array( $data ) ) {
				$error = 'JSONの解析に失敗しました。';
			} else {
				$stored = get_option( self::OPTION_LIST, array() );
				$stored['domains']    = self::sanitize_lines( isset( $data['domains'] ) ? $data['domains'] : array() );
				$stored['keywords']   = self::sanitize_lines( isset( $data['keywords'] ) ? $data['keywords'] : array() );
				$stored['fetched_at'] = time();
				$stored['error']      = '';
				update_option( self::OPTION_LIST, $stored, false );
				return true;
			}
		}

		$stored          = get_option( self::OPTION_LIST, array() );
		$stored['error'] = $error;
		update_option( self::OPTION_LIST, $stored, false );

		return new WP_Error( 'cf7sb_fetch_failed', $error );
	}

	/**
	 * 編集内容を中央サーバーへ書き戻す。成功したらローカルキャッシュも更新。
	 *
	 * @param string[] $domains
	 * @param string[] $keywords
	 * @return true|WP_Error
	 */
	public static function push( $domains, $keywords ) {
		$url = self::get_setting( 'url' );
		$key = self::get_setting( 'key' );

		if ( ! $url ) {
			return new WP_Error( 'cf7sb_no_url', 'ブロックリストURLが設定されていません。' );
		}
		if ( ! $key ) {
			return new WP_Error( 'cf7sb_no_key', '書き込み用秘密キーが設定されていないため、編集内容を保存できません。' );
		}

		$body = wp_json_encode( array(
			'domains'  => self::sanitize_lines( $domains ),
			'keywords' => self::sanitize_lines( $keywords ),
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

		self::refresh();
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
