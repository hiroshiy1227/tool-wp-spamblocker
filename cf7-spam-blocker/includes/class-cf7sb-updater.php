<?php
/**
 * 独自更新サーバー対応。
 *
 * プラグインヘッダーの「Update URI」に応じて2方式をサポート:
 *   1. GitHubリポジトリURL（https://github.com/owner/repo）
 *      → Releases API の最新リリースのタグ（v1.2.3）とzipアセットを参照。
 *        リリースを作るだけで全サイトに更新通知が届く。
 *   2. それ以外のURL → info.json（version / package 等）として直接参照。
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class CF7SB_Updater {

	const CACHE_KEY = 'cf7sb_update_info';

	public static function init() {
		$uri = self::update_uri();
		if ( ! $uri || false !== strpos( $uri, 'OWNER/REPO' ) ) {
			return; // Update URI が未設定（雛形のまま）なら何もしない
		}
		$host = wp_parse_url( $uri, PHP_URL_HOST );
		if ( ! $host || 'example.com' === $host ) {
			return;
		}
		add_filter( "update_plugins_{$host}", array( __CLASS__, 'check_update' ), 10, 3 );
	}

	private static function update_uri() {
		$data = get_file_data( CF7SB_FILE, array( 'UpdateURI' => 'Update URI' ) );
		return isset( $data['UpdateURI'] ) ? trim( $data['UpdateURI'] ) : '';
	}

	/**
	 * update_plugins_{$hostname} フィルター。
	 * 自分のプラグインの場合のみ更新情報を返す。
	 */
	public static function check_update( $update, $plugin_data, $plugin_file ) {
		if ( plugin_basename( CF7SB_FILE ) !== $plugin_file ) {
			return $update;
		}

		$info = self::fetch_info();
		if ( ! $info || empty( $info['version'] ) || empty( $info['package'] ) ) {
			return $update;
		}

		if ( version_compare( $info['version'], CF7SB_VERSION, '<=' ) ) {
			return $update;
		}

		return array(
			'id'           => self::update_uri(),
			'slug'         => dirname( $plugin_file ),
			'plugin'       => $plugin_file,
			'version'      => $info['version'],
			'url'          => isset( $info['url'] ) ? $info['url'] : '',
			'package'      => $info['package'],
			'tested'       => isset( $info['tested'] ) ? $info['tested'] : '',
			'requires'     => isset( $info['requires'] ) ? $info['requires'] : '',
			'requires_php' => isset( $info['requires_php'] ) ? $info['requires_php'] : '',
		);
	}

	/**
	 * 更新情報を取得（6時間キャッシュ、失敗時は1時間キャッシュ）。
	 *
	 * @return array|null
	 */
	private static function fetch_info() {
		$cached = get_site_transient( self::CACHE_KEY );
		if ( is_array( $cached ) ) {
			return $cached ? $cached : null;
		}

		$uri  = self::update_uri();
		$host = wp_parse_url( $uri, PHP_URL_HOST );

		$info = ( 'github.com' === $host )
			? self::fetch_from_github( $uri )
			: self::fetch_from_json( $uri );

		if ( null === $info ) {
			set_site_transient( self::CACHE_KEY, array(), HOUR_IN_SECONDS );
			return null;
		}

		set_site_transient( self::CACHE_KEY, $info, 6 * HOUR_IN_SECONDS );
		return $info;
	}

	/**
	 * GitHub Releases API から最新リリースを取得。
	 * バージョンはタグ名（v1.2.3 または 1.2.3）、パッケージはzipアセット。
	 */
	private static function fetch_from_github( $uri ) {
		$repo = trim( (string) wp_parse_url( $uri, PHP_URL_PATH ), '/' );
		$repo = preg_replace( '/\.git$/', '', $repo );
		if ( ! preg_match( '#^[^/]+/[^/]+$#', $repo ) ) {
			return null;
		}

		$response = wp_remote_get(
			'https://api.github.com/repos/' . $repo . '/releases/latest',
			array(
				'timeout' => 10,
				'headers' => array( 'Accept' => 'application/vnd.github+json' ),
			)
		);
		if ( is_wp_error( $response ) || 200 !== wp_remote_retrieve_response_code( $response ) ) {
			return null;
		}

		$release = json_decode( wp_remote_retrieve_body( $response ), true );
		if ( ! is_array( $release ) || empty( $release['tag_name'] ) ) {
			return null;
		}

		$package = '';
		if ( ! empty( $release['assets'] ) && is_array( $release['assets'] ) ) {
			foreach ( $release['assets'] as $asset ) {
				if ( ! empty( $asset['browser_download_url'] ) && '.zip' === substr( $asset['name'], -4 ) ) {
					$package = $asset['browser_download_url'];
					// プラグイン名で始まるzipを最優先。なければ最初のzip
					if ( 0 === strpos( $asset['name'], 'cf7-spam-blocker' ) ) {
						break;
					}
				}
			}
		}
		if ( ! $package ) {
			return null; // zipアセットのないリリース（ビルド失敗など）は無視
		}

		return array(
			'version' => ltrim( $release['tag_name'], 'vV' ),
			'package' => $package,
			'url'     => isset( $release['html_url'] ) ? $release['html_url'] : '',
		);
	}

	/**
	 * info.json 方式（GitHub以外の自前サーバー用）。
	 */
	private static function fetch_from_json( $uri ) {
		$response = wp_remote_get( $uri, array( 'timeout' => 10 ) );
		if ( is_wp_error( $response ) || 200 !== wp_remote_retrieve_response_code( $response ) ) {
			return null;
		}

		$info = json_decode( wp_remote_retrieve_body( $response ), true );
		return is_array( $info ) ? $info : null;
	}
}
