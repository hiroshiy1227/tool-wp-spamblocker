<?php
/**
 * CF7 Spam Blocker - ブロックリスト配信・受付API（WordPress不要の単体ファイル）
 *
 * 設置方法:
 *   1. このファイルをサーバーの任意の場所に置く（例: https://example.com/cf7sb/blocklist-api.php）
 *   2. 下の CF7SB_API_KEY を推測されない長いランダム文字列に変更する
 *   3. 各サイトのプラグイン設定で URL と同じキーを設定する
 *
 * 使い方:
 *   GET  ?list=default          → リストのJSONを返す
 *   POST ?list=default          → X-CF7SB-Key ヘッダーのキーが一致すればリストを上書き保存
 *
 * リスト名を変えれば複数のリスト（会社A用・会社B用など）を1つの設置で管理できます。
 */

// ★必ず変更してください（例: openssl rand -hex 32 で生成）
const CF7SB_API_KEY = 'CHANGE-ME-TO-A-LONG-RANDOM-STRING';

const CF7SB_LISTS_DIR   = __DIR__ . '/lists';
const CF7SB_MAX_ITEMS   = 5000;      // 1リストあたりの最大件数
const CF7SB_MAX_BODY    = 1048576;   // 受け付けるリクエストボディの上限（1MB）

header( 'Content-Type: application/json; charset=utf-8' );
header( 'X-Content-Type-Options: nosniff' );

function cf7sb_respond( $code, $data ) {
	http_response_code( $code );
	echo json_encode( $data, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES );
	exit;
}

if ( 0 === strpos( CF7SB_API_KEY, 'CHANGE-ME' ) || strlen( CF7SB_API_KEY ) < 16 ) {
	cf7sb_respond( 500, array( 'error' => 'CF7SB_API_KEY が初期値のまま、または短すぎます（16文字以上）。blocklist-api.php を編集してください。' ) );
}

$list = isset( $_GET['list'] ) ? $_GET['list'] : 'default';
if ( ! preg_match( '/^[a-zA-Z0-9_-]{1,50}$/', $list ) ) {
	cf7sb_respond( 400, array( 'error' => 'リスト名は半角英数字・ハイフン・アンダースコアのみ使用できます。' ) );
}
$file = CF7SB_LISTS_DIR . '/' . $list . '.json';

$method = $_SERVER['REQUEST_METHOD'];

if ( 'GET' === $method ) {
	if ( ! is_file( $file ) ) {
		cf7sb_respond( 200, array( 'domains' => array(), 'emails' => array(), 'keywords' => array(), 'updated' => null ) );
	}
	readfile( $file );
	exit;
}

if ( 'POST' === $method ) {
	$sent_key = isset( $_SERVER['HTTP_X_CF7SB_KEY'] ) ? $_SERVER['HTTP_X_CF7SB_KEY'] : '';
	if ( ! hash_equals( CF7SB_API_KEY, $sent_key ) ) {
		cf7sb_respond( 403, array( 'error' => '秘密キーが一致しません。' ) );
	}

	$body = file_get_contents( 'php://input', false, null, 0, CF7SB_MAX_BODY + 1 );
	if ( strlen( $body ) > CF7SB_MAX_BODY ) {
		cf7sb_respond( 413, array( 'error' => 'リクエストが大きすぎます。' ) );
	}

	$data = json_decode( $body, true );
	if ( ! is_array( $data ) ) {
		cf7sb_respond( 400, array( 'error' => 'JSONの解析に失敗しました。' ) );
	}

	$clean = array( 'domains' => array(), 'emails' => array(), 'keywords' => array() );
	foreach ( array( 'domains', 'emails', 'keywords' ) as $field ) {
		$items = isset( $data[ $field ] ) && is_array( $data[ $field ] ) ? $data[ $field ] : array();
		foreach ( $items as $item ) {
			if ( ! is_string( $item ) ) {
				continue;
			}
			$item = trim( $item );
			if ( '' === $item || mb_strlen( $item ) > 200 ) {
				continue;
			}
			$clean[ $field ][] = $item;
		}
		$clean[ $field ] = array_values( array_unique( $clean[ $field ] ) );
		if ( count( $clean[ $field ] ) > CF7SB_MAX_ITEMS ) {
			cf7sb_respond( 400, array( 'error' => '件数が上限を超えています。' ) );
		}
	}
	$clean['updated'] = date( 'c' );

	if ( ! is_dir( CF7SB_LISTS_DIR ) && ! mkdir( CF7SB_LISTS_DIR, 0755, true ) ) {
		cf7sb_respond( 500, array( 'error' => '保存先ディレクトリを作成できません。' ) );
	}

	$json = json_encode( $clean, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT );
	if ( false === file_put_contents( $file, $json, LOCK_EX ) ) {
		cf7sb_respond( 500, array( 'error' => 'ファイルの書き込みに失敗しました。' ) );
	}

	cf7sb_respond( 200, $clean );
}

cf7sb_respond( 405, array( 'error' => 'GET または POST のみ対応しています。' ) );
