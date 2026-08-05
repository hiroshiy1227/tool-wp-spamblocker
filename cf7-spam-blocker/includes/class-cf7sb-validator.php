<?php
/**
 * Contact Form 7 のバリデーション／スパム判定フック。
 *
 * ブロック時の動作（設定 mode）:
 *   field         … 該当フィールドにエラーを表示（原因が相手に分かる）
 *   stealth_error … どの欄が原因か伏せて「送信に失敗しました」風の表示（wpcf7_spam）
 *   fake_success  … 成功画面を見せて実際には送信しない（wpcf7_before_send_mail で中断）
 *
 * 判定内容:
 * ・メール欄: 拒否メールアドレス（完全一致）／拒否ドメイン（サブドメイン含む完全一致）
 * ・テキスト/本文欄: 拒否ドメイン・拒否メールアドレス・拒否文字列を含むか
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class CF7SB_Validator {

	public static function init() {
		add_filter( 'wpcf7_validate_email',  array( __CLASS__, 'validate_email' ), 10, 2 );
		add_filter( 'wpcf7_validate_email*', array( __CLASS__, 'validate_email' ), 10, 2 );

		add_filter( 'wpcf7_validate_text',      array( __CLASS__, 'validate_text' ), 10, 2 );
		add_filter( 'wpcf7_validate_text*',     array( __CLASS__, 'validate_text' ), 10, 2 );
		add_filter( 'wpcf7_validate_textarea',  array( __CLASS__, 'validate_text' ), 10, 2 );
		add_filter( 'wpcf7_validate_textarea*', array( __CLASS__, 'validate_text' ), 10, 2 );

		add_filter( 'wpcf7_spam', array( __CLASS__, 'spam_check' ), 10, 2 );
		add_action( 'wpcf7_before_send_mail', array( __CLASS__, 'maybe_fake_success' ), 10, 3 );
	}

	private static function mode() {
		$mode = CF7SB_Blocklist::get_setting( 'mode' );
		return in_array( $mode, array( 'field', 'stealth_error', 'fake_success' ), true ) ? $mode : 'field';
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

	private static function posted_value( $tag ) {
		if ( ! isset( $_POST[ $tag->name ] ) ) {
			return null;
		}
		$value = wp_unslash( $_POST[ $tag->name ] );
		if ( is_array( $value ) ) {
			$value = implode( ' ', $value );
		}
		return (string) $value;
	}

	public static function validate_email( $result, $tag ) {
		if ( 'field' !== self::mode() ) {
			return $result; // ステルス系モードでは送信段階（spam判定/送信中断）で処理する
		}
		$value = self::posted_value( $tag );
		if ( null !== $value && self::is_blocked_email_value( $value ) ) {
			$result->invalidate( $tag, CF7SB_Blocklist::get_setting( 'message' ) );
		}
		return $result;
	}

	public static function validate_text( $result, $tag ) {
		if ( 'field' !== self::mode() ) {
			return $result;
		}
		$value = self::posted_value( $tag );
		if ( null !== $value && self::is_blocked_text_value( $value ) ) {
			$result->invalidate( $tag, CF7SB_Blocklist::get_setting( 'message' ) );
		}
		return $result;
	}

	/**
	 * 送信データ全体をチェックしてブロック対象か判定する（ステルス系モード用）。
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
			$type = $tag->basetype;
			if ( ! in_array( $type, array( 'email', 'text', 'textarea' ), true ) ) {
				continue;
			}
			$value = isset( $data[ $tag->name ] ) ? $data[ $tag->name ] : '';
			if ( is_array( $value ) ) {
				$value = implode( ' ', $value );
			}
			if ( 'email' === $type ) {
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
	 * stealth_error: スパム扱いにして「送信に失敗しました」風の汎用エラーを表示させる。
	 * どのフィールドが原因かは一切表示されない。
	 */
	public static function spam_check( $spam, $submission = null ) {
		if ( $spam ) {
			return $spam;
		}
		if ( 'stealth_error' !== self::mode() ) {
			return $spam;
		}
		return self::submission_blocked( $submission );
	}

	/**
	 * fake_success: メール送信を中断しつつ、成功時と同じ表示を返す。
	 */
	public static function maybe_fake_success( $contact_form, &$abort, $submission ) {
		if ( 'fake_success' !== self::mode() ) {
			return;
		}
		if ( ! self::submission_blocked( $submission ) ) {
			return;
		}
		$abort = true;
		$submission->set_status( 'mail_sent' );
		$submission->set_response( $contact_form->message( 'mail_sent_ok' ) );
	}
}
