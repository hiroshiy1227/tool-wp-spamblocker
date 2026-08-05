<?php
/**
 * 中央サーバー機能（かんたんセットアップ方式）。
 *
 * 「このサイトを中央サーバーにする」を有効にすると、プラグイン自身が
 * WordPress REST API（/wp-json/cf7sb/v1/list）でブロックリストを配信・受付する。
 * 外部PHPファイルの設置・FTP・キーファイルの同期が一切不要になる。
 *
 * リストは wp_options（cf7sb_server_lists）に保存され、?list= 名ごとに分かれる。
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class CF7SB_Server {

	const OPTION_ENABLED = 'cf7sb_server_enabled';
	const OPTION_KEY     = 'cf7sb_server_key';
	const OPTION_LISTS   = 'cf7sb_server_lists';

	public static function init() {
		add_action( 'rest_api_init', array( __CLASS__, 'register_routes' ) );
	}

	public static function is_enabled() {
		return (bool) get_option( self::OPTION_ENABLED, false );
	}

	public static function get_key() {
		return (string) get_option( self::OPTION_KEY, '' );
	}

	/**
	 * このサイトの配信URL（既定リスト）。
	 */
	public static function list_url( $list = 'default' ) {
		return add_query_arg( 'list', rawurlencode( $list ), rest_url( 'cf7sb/v1/list' ) );
	}

	/**
	 * 中央サーバー化する。キーを用意し、このサイト自身の接続設定も自動で整える。
	 * 既に取得済みのリストキャッシュがあれば初期データとして取り込む（移行を簡単に）。
	 */
	public static function enable() {
		update_option( self::OPTION_ENABLED, 1, false );

		$settings = CF7SB_Blocklist::get_settings();

		$key = self::get_key();
		if ( '' === $key ) {
			$key = '' !== $settings['key'] ? $settings['key'] : 'cf7sb-' . bin2hex( random_bytes( 20 ) );
			update_option( self::OPTION_KEY, $key, false );
		}

		$settings['key'] = $key;
		$settings['url'] = self::list_url();
		update_option( CF7SB_Blocklist::OPTION_SETTINGS, $settings, false );

		// 旧方式で取得済みのリストがあれば、サーバー側の初期データとして引き継ぐ
		$lists = get_option( self::OPTION_LISTS, array() );
		if ( empty( $lists['default'] ) ) {
			$cached = get_option( CF7SB_Blocklist::OPTION_LIST, array() );
			if ( ! empty( $cached['domains'] ) || ! empty( $cached['emails'] ) || ! empty( $cached['keywords'] ) || ! empty( $cached['message'] ) ) {
				$lists['default'] = array(
					'domains'  => isset( $cached['domains'] ) ? (array) $cached['domains'] : array(),
					'emails'   => isset( $cached['emails'] ) ? (array) $cached['emails'] : array(),
					'keywords' => isset( $cached['keywords'] ) ? (array) $cached['keywords'] : array(),
					'message'  => isset( $cached['message'] ) ? (string) $cached['message'] : '',
					'updated'  => date( 'c' ),
				);
				update_option( self::OPTION_LISTS, $lists, false );
			}
		}

		CF7SB_Blocklist::refresh();
	}

	public static function disable() {
		delete_option( self::OPTION_ENABLED ); // リストデータとキーは保持（再有効化に備える）
	}

	private static function sanitize_list_name( $name ) {
		$name = is_string( $name ) ? $name : 'default';
		return preg_match( '/^[a-zA-Z0-9_-]{1,50}$/', $name ) ? $name : 'default';
	}

	/**
	 * @return array{domains: array, emails: array, keywords: array, message: string, updated: ?string}
	 */
	public static function get_list( $name ) {
		$lists = get_option( self::OPTION_LISTS, array() );
		$name  = self::sanitize_list_name( $name );
		$list  = isset( $lists[ $name ] ) && is_array( $lists[ $name ] ) ? $lists[ $name ] : array();
		return array(
			'domains'    => isset( $list['domains'] ) ? (array) $list['domains'] : array(),
			'emails'     => isset( $list['emails'] ) ? (array) $list['emails'] : array(),
			'keywords'   => isset( $list['keywords'] ) ? (array) $list['keywords'] : array(),
			'patterns'   => isset( $list['patterns'] ) ? (array) $list['patterns'] : array(),
			'message'    => isset( $list['message'] ) ? (string) $list['message'] : '',
			'block_uuid' => isset( $list['block_uuid'] ) ? (bool) $list['block_uuid'] : true,
			'updated'    => isset( $list['updated'] ) ? $list['updated'] : null,
		);
	}

	/**
	 * リストを保存して、保存後の内容を返す。
	 */
	public static function save_list( $name, $data ) {
		$name  = self::sanitize_list_name( $name );
		$clean = array(
			'domains'  => CF7SB_Blocklist::sanitize_lines( isset( $data['domains'] ) ? $data['domains'] : array() ),
			'emails'   => CF7SB_Blocklist::sanitize_lines( isset( $data['emails'] ) ? $data['emails'] : array() ),
			'keywords' => CF7SB_Blocklist::sanitize_lines( isset( $data['keywords'] ) ? $data['keywords'] : array() ),
			'patterns' => CF7SB_Blocklist::sanitize_patterns( isset( $data['patterns'] ) ? $data['patterns'] : array() ),
			'block_uuid' => isset( $data['block_uuid'] ) ? (bool) $data['block_uuid'] : true,
			'message'  => isset( $data['message'] ) && is_string( $data['message'] )
				? mb_substr( trim( wp_strip_all_tags( $data['message'] ) ), 0, 500 )
				: '',
			'updated'  => date( 'c' ),
		);

		$lists          = get_option( self::OPTION_LISTS, array() );
		$lists[ $name ] = $clean;
		update_option( self::OPTION_LISTS, $lists, false );

		return $clean;
	}

	/**
	 * URLがこのサイト自身の配信URLを指しているならリスト名を返す（HTTPを介さない近道用）。
	 *
	 * @return string|null
	 */
	public static function local_list_name( $url ) {
		if ( ! self::is_enabled() || ! $url ) {
			return null;
		}
		$u    = wp_parse_url( $url );
		$site = wp_parse_url( home_url() );
		if ( empty( $u['host'] ) || empty( $site['host'] )
			|| strtolower( $u['host'] ) !== strtolower( $site['host'] ) ) {
			return null;
		}
		$u_port = isset( $u['port'] ) ? (int) $u['port'] : 0;
		$s_port = isset( $site['port'] ) ? (int) $site['port'] : 0;
		if ( $u_port !== $s_port ) {
			return null;
		}

		$args = array();
		if ( ! empty( $u['query'] ) ) {
			parse_str( $u['query'], $args );
		}
		$path_hit  = ! empty( $u['path'] ) && false !== strpos( $u['path'], '/cf7sb/v1/list' );
		$route_hit = ! empty( $args['rest_route'] ) && false !== strpos( (string) $args['rest_route'], '/cf7sb/v1/list' );
		if ( ! $path_hit && ! $route_hit ) {
			return null;
		}

		return self::sanitize_list_name( isset( $args['list'] ) ? $args['list'] : 'default' );
	}

	public static function register_routes() {
		if ( ! self::is_enabled() ) {
			return;
		}
		register_rest_route(
			'cf7sb/v1',
			'/list',
			array(
				array(
					'methods'             => 'GET',
					'callback'            => array( __CLASS__, 'handle_get' ),
					'permission_callback' => '__return_true',
				),
				array(
					'methods'             => 'POST',
					'callback'            => array( __CLASS__, 'handle_post' ),
					'permission_callback' => '__return_true',
				),
			)
		);
	}

	public static function handle_get( $request ) {
		$response = rest_ensure_response( self::get_list( $request->get_param( 'list' ) ) );
		$response->header( 'Cache-Control', 'no-store' );
		return $response;
	}

	public static function handle_post( $request ) {
		$sent_key = (string) $request->get_header( 'X-CF7SB-Key' );
		$key      = self::get_key();
		if ( '' === $key || ! hash_equals( $key, $sent_key ) ) {
			return new WP_Error( 'cf7sb_forbidden', '秘密キーが一致しません。', array( 'status' => 403 ) );
		}

		$data = $request->get_json_params();
		if ( ! is_array( $data ) ) {
			return new WP_Error( 'cf7sb_bad_request', 'JSONの解析に失敗しました。', array( 'status' => 400 ) );
		}

		return rest_ensure_response( self::save_list( $request->get_param( 'list' ), $data ) );
	}
}
