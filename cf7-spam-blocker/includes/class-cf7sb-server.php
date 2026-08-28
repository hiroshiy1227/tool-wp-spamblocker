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
			'block_link' => isset( $list['block_link'] ) ? (bool) $list['block_link'] : false,
			// v2.12.0で相互リンクフィルターから分離。未保存の間は旧設定を引き継ぐ（更新直後の保護切れを防ぐ）
			'block_sales' => isset( $list['block_sales'] ) ? (bool) $list['block_sales'] : ( isset( $list['block_link'] ) && (bool) $list['block_link'] ),
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
			'block_link' => isset( $data['block_link'] ) ? (bool) $data['block_link'] : false,
			'block_sales' => isset( $data['block_sales'] ) ? (bool) $data['block_sales'] : false,
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

	/** 接続サイト一覧の保存先と保持件数 */
	const OPTION_SITES = 'cf7sb_server_sites';
	const MAX_SITES    = 100;

	/**
	 * リストを取得しにきたサイトを記録する（プラグイン導入サイトの一覧用）。
	 * サイトURLをキーにするため、同じサイトからの再取得では最終確認日時が更新される。
	 */
	public static function record_site( $args ) {
		$url = isset( $args['url'] ) ? esc_url_raw( (string) $args['url'] ) : '';
		if ( '' === $url ) {
			return false;
		}

		$sites = get_option( self::OPTION_SITES, array() );
		$id    = md5( untrailingslashit( strtolower( $url ) ) );

		$sites[ $id ] = array(
			'url'       => $url,
			'name'      => mb_substr( sanitize_text_field( (string) ( isset( $args['name'] ) ? $args['name'] : '' ) ), 0, 100 ),
			'version'   => preg_replace( '/[^0-9.]/', '', (string) ( isset( $args['version'] ) ? $args['version'] : '' ) ),
			'list'      => self::sanitize_list_name( isset( $args['list'] ) ? $args['list'] : 'default' ),
			'role'      => ( isset( $args['role'] ) && 'central' === $args['role'] ) ? 'central' : 'client',
			'last_seen' => time(),
		);

		// 古い記録から溢れさせる（最終確認が新しい順に保持）
		if ( count( $sites ) > self::MAX_SITES ) {
			uasort( $sites, function ( $a, $b ) {
				return $b['last_seen'] <=> $a['last_seen'];
			} );
			$sites = array_slice( $sites, 0, self::MAX_SITES, true );
		}

		update_option( self::OPTION_SITES, $sites, false );
		return true;
	}

	/**
	 * 接続サイト一覧（最終確認が新しい順）。
	 */
	public static function get_sites() {
		$sites = get_option( self::OPTION_SITES, array() );
		if ( ! is_array( $sites ) ) {
			return array();
		}
		uasort( $sites, function ( $a, $b ) {
			// 中央サーバーを先頭に、あとは最終確認が新しい順
			if ( ( 'central' === $a['role'] ) !== ( 'central' === $b['role'] ) ) {
				return ( 'central' === $a['role'] ) ? -1 : 1;
			}
			return $b['last_seen'] <=> $a['last_seen'];
		} );
		foreach ( $sites as $id => $site ) {
			$sites[ $id ]['id'] = $id;
		}
		return array_values( $sites );
	}

	public static function remove_site( $id ) {
		$sites = get_option( self::OPTION_SITES, array() );
		unset( $sites[ (string) $id ] );
		update_option( self::OPTION_SITES, $sites, false );
		return true;
	}

	/** ブロックログの保存先と保持件数（リストごと） */
	const OPTION_LOGS = 'cf7sb_server_logs';
	const MAX_LOGS    = 500;

	/**
	 * ログ1件を正規化する（保存する情報を限定し、長さも制限する）。
	 */
	private static function sanitize_log_entry( $entry ) {
		$text = function ( $value, $length ) {
			return mb_substr( trim( wp_strip_all_tags( (string) $value ) ), 0, $length );
		};
		return array(
			'time'    => isset( $entry['time'] ) ? (int) $entry['time'] : time(),
			'site'    => $text( isset( $entry['site'] ) ? $entry['site'] : '', 100 ),
			'form'    => $text( isset( $entry['form'] ) ? $entry['form'] : '', 100 ),
			'rule'    => preg_replace( '/[^a-z_]/', '', (string) ( isset( $entry['rule'] ) ? $entry['rule'] : '' ) ),
			'matched' => $text( isset( $entry['matched'] ) ? $entry['matched'] : '', 200 ),
			'field'   => $text( isset( $entry['field'] ) ? $entry['field'] : '', 100 ),
			'email'   => $text( isset( $entry['email'] ) ? $entry['email'] : '', 200 ),
			'excerpt' => $text( isset( $entry['excerpt'] ) ? $entry['excerpt'] : '', 2000 ),
			'ip'      => $text( isset( $entry['ip'] ) ? $entry['ip'] : '', 45 ),
		);
	}

	/**
	 * ブロックログを1件追加する（新しいものが先頭）。
	 */
	public static function add_log( $name, $entry ) {
		$name = self::sanitize_list_name( $name );
		$logs = get_option( self::OPTION_LOGS, array() );
		$list = ( isset( $logs[ $name ] ) && is_array( $logs[ $name ] ) ) ? $logs[ $name ] : array();

		array_unshift( $list, self::sanitize_log_entry( $entry ) );
		if ( count( $list ) > self::MAX_LOGS ) {
			$list = array_slice( $list, 0, self::MAX_LOGS );
		}

		$logs[ $name ] = $list;
		update_option( self::OPTION_LOGS, $logs, false );
		return true;
	}

	/**
	 * @return array{logs: array, total: int, counts: array}
	 */
	public static function get_logs( $name, $limit = 100 ) {
		$name = self::sanitize_list_name( $name );
		$logs = get_option( self::OPTION_LOGS, array() );
		$list = ( isset( $logs[ $name ] ) && is_array( $logs[ $name ] ) ) ? $logs[ $name ] : array();

		// 理由別の内訳（保存されている全件が対象）
		$counts = array();
		foreach ( $list as $row ) {
			$rule            = isset( $row['rule'] ) ? $row['rule'] : '';
			$counts[ $rule ] = isset( $counts[ $rule ] ) ? $counts[ $rule ] + 1 : 1;
		}
		arsort( $counts );

		return array(
			'logs'   => array_slice( $list, 0, max( 1, (int) $limit ) ),
			'total'  => count( $list ),
			'counts' => $counts,
		);
	}

	public static function clear_logs( $name ) {
		$name = self::sanitize_list_name( $name );
		$logs = get_option( self::OPTION_LOGS, array() );
		unset( $logs[ $name ] );
		update_option( self::OPTION_LOGS, $logs, false );
		return true;
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
		// ログは送信内容を含むため、閲覧・記録・消去のすべてに秘密キーを要求する
		register_rest_route(
			'cf7sb/v1',
			'/log',
			array(
				array(
					'methods'             => 'GET',
					'callback'            => array( __CLASS__, 'handle_log_get' ),
					'permission_callback' => '__return_true',
				),
				array(
					'methods'             => 'POST',
					'callback'            => array( __CLASS__, 'handle_log_post' ),
					'permission_callback' => '__return_true',
				),
				array(
					'methods'             => 'DELETE',
					'callback'            => array( __CLASS__, 'handle_log_delete' ),
					'permission_callback' => '__return_true',
				),
			)
		);
		register_rest_route(
			'cf7sb/v1',
			'/sites',
			array(
				array(
					'methods'             => 'GET',
					'callback'            => array( __CLASS__, 'handle_sites_get' ),
					'permission_callback' => '__return_true',
				),
				array(
					'methods'             => 'DELETE',
					'callback'            => array( __CLASS__, 'handle_sites_delete' ),
					'permission_callback' => '__return_true',
				),
			)
		);
	}

	public static function handle_sites_get( $request ) {
		$allowed = self::check_key( $request );
		if ( is_wp_error( $allowed ) ) {
			return $allowed;
		}
		$response = rest_ensure_response( array( 'sites' => self::get_sites() ) );
		$response->header( 'Cache-Control', 'no-store' );
		return $response;
	}

	public static function handle_sites_delete( $request ) {
		$allowed = self::check_key( $request );
		if ( is_wp_error( $allowed ) ) {
			return $allowed;
		}
		self::remove_site( $request->get_param( 'id' ) );
		return rest_ensure_response( array( 'removed' => true ) );
	}

	/**
	 * 秘密キーを照合する。一致しなければ WP_Error を返す。
	 *
	 * @return true|WP_Error
	 */
	private static function check_key( $request ) {
		$sent_key = (string) $request->get_header( 'X-CF7SB-Key' );
		$key      = self::get_key();
		if ( '' === $key || ! hash_equals( $key, $sent_key ) ) {
			return new WP_Error( 'cf7sb_forbidden', '秘密キーが一致しません。', array( 'status' => 403 ) );
		}
		return true;
	}

	public static function handle_log_get( $request ) {
		$allowed = self::check_key( $request );
		if ( is_wp_error( $allowed ) ) {
			return $allowed;
		}
		$limit    = (int) $request->get_param( 'limit' );
		$response = rest_ensure_response( self::get_logs( $request->get_param( 'list' ), $limit ? $limit : 100 ) );
		$response->header( 'Cache-Control', 'no-store' );
		return $response;
	}

	public static function handle_log_post( $request ) {
		$allowed = self::check_key( $request );
		if ( is_wp_error( $allowed ) ) {
			return $allowed;
		}
		$data = $request->get_json_params();
		if ( ! is_array( $data ) ) {
			return new WP_Error( 'cf7sb_bad_request', 'JSONの解析に失敗しました。', array( 'status' => 400 ) );
		}
		self::add_log( $request->get_param( 'list' ), $data );
		return rest_ensure_response( array( 'logged' => true ) );
	}

	public static function handle_log_delete( $request ) {
		$allowed = self::check_key( $request );
		if ( is_wp_error( $allowed ) ) {
			return $allowed;
		}
		self::clear_logs( $request->get_param( 'list' ) );
		return rest_ensure_response( array( 'cleared' => true ) );
	}

	public static function handle_get( $request ) {
		// 秘密キーが一致する取得元は、接続サイトとして記録する（追加のリクエストは不要）
		$key      = self::get_key();
		$sent_key = (string) $request->get_header( 'X-CF7SB-Key' );
		if ( '' !== $key && hash_equals( $key, $sent_key ) && $request->get_param( 'site_url' ) ) {
			self::record_site( array(
				'url'     => $request->get_param( 'site_url' ),
				'name'    => $request->get_param( 'site_name' ),
				'version' => $request->get_param( 'ver' ),
				'list'    => $request->get_param( 'list' ),
				'role'    => 'client',
			) );
		}

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
