<?php
/**
 * Contact Form 7 の迷惑送信判定。
 *
 * ブロック時はフォーム全体のメッセージとして拒否理由を1回だけ表示する。
 * 個々の入力欄にはエラーを出さない（どの項目が原因かを送信者に推測させないため）。
 *
 * 判定内容:
 * ・メール欄: 拒否メールアドレス（完全一致）／拒否ドメイン（サブドメイン含む完全一致）
 * ・テキスト/本文欄: 拒否ドメイン・拒否メールアドレス・拒否文字列を含むか
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class CF7SB_Validator {

	/** このリクエストで自プラグインがブロック判定したか */
	private static $blocked = false;

	public static function init() {
		add_filter( 'wpcf7_spam', array( __CLASS__, 'spam_check' ), 10, 2 );
		add_filter( 'wpcf7_display_message', array( __CLASS__, 'filter_display_message' ), 10, 2 );
	}

	/**
	 * メール欄の値がブロック対象か（拒否メールアドレス完全一致／拒否ドメイン）。
	 */
	public static function is_blocked_email_value( $value ) {
		$value = strtolower( trim( (string) $value ) );
		if ( '' === $value ) {
			return false;
		}
		$list = CF7SB_Blocklist::get();

		foreach ( $list['emails'] as $email ) {
			if ( strtolower( trim( $email ) ) === $value ) {
				return true;
			}
		}
		foreach ( $list['domains'] as $domain ) {
			// 完全一致＋サブドメインも対象
			if ( preg_match( '/@([a-z0-9\-]+\.)*' . preg_quote( strtolower( $domain ), '/' ) . '$/i', $value ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * テキスト/本文欄の値がブロック対象か（拒否ドメイン・拒否メールアドレス・拒否文字列を含む）。
	 */
	public static function is_blocked_text_value( $value ) {
		$value = (string) $value;
		if ( '' === $value ) {
			return false;
		}
		$list    = CF7SB_Blocklist::get();
		$needles = array_merge( $list['domains'], $list['emails'], $list['keywords'] );

		foreach ( $needles as $needle ) {
			if ( false !== stripos( $value, $needle ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * 送信データ全体をチェックしてブロック対象か判定する。
	 */
	public static function submission_blocked( $submission ) {
		if ( ! $submission || ! method_exists( $submission, 'get_contact_form' ) ) {
			return false;
		}
		$form = $submission->get_contact_form();
		$data = $submission->get_posted_data();
		if ( ! $form || ! is_array( $data ) ) {
			return false;
		}

		foreach ( $form->scan_form_tags() as $tag ) {
			if ( ! in_array( $tag->basetype, array( 'email', 'text', 'textarea' ), true ) ) {
				continue;
			}
			$value = isset( $data[ $tag->name ] ) ? $data[ $tag->name ] : '';
			if ( is_array( $value ) ) {
				$value = implode( ' ', $value );
			}
			if ( 'email' === $tag->basetype ) {
				if ( self::is_blocked_email_value( $value ) ) {
					return true;
				}
			} elseif ( self::is_blocked_text_value( $value ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * スパム扱いにして送信を止める。個々のフィールドにはエラーを付けない。
	 */
	public static function spam_check( $spam, $submission = null ) {
		if ( $spam ) {
			return $spam; // 他プラグイン（Akismet等）の判定を尊重
		}
		if ( self::submission_blocked( $submission ) ) {
			self::$blocked = true;
			return true;
		}
		return $spam;
	}

	/**
	 * 自プラグインがブロックした場合のみ、フォーム全体のメッセージを差し替える。
	 */
	public static function filter_display_message( $message, $status = '' ) {
		if ( self::$blocked && 'spam' === $status ) {
			$custom = CF7SB_Blocklist::get_setting( 'message' );
			if ( '' !== $custom ) {
				return $custom;
			}
		}
		return $message;
	}
}
