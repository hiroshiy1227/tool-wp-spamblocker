<?php
/**
 * Contact Form 7 のバリデーションフック。
 * ・メール欄: 拒否ドメイン（サブドメイン含む完全一致）
 * ・テキスト/本文欄: 拒否ドメインまたは拒否文字列を含むか
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
		$value = self::posted_value( $tag );
		if ( null === $value || '' === $value ) {
			return $result;
		}

		$value = strtolower( trim( $value ) );
		$list  = CF7SB_Blocklist::get();

		// 拒否メールアドレス（完全一致）
		foreach ( $list['emails'] as $email ) {
			if ( strtolower( trim( $email ) ) === $value ) {
				$result->invalidate( $tag, CF7SB_Blocklist::get_setting( 'message' ) );
				return $result;
			}
		}

		foreach ( $list['domains'] as $domain ) {
			$domain = strtolower( $domain );
			// 完全一致＋サブドメインも対象
			if ( preg_match( '/@([a-z0-9\-]+\.)*' . preg_quote( $domain, '/' ) . '$/i', $value ) ) {
				$result->invalidate( $tag, CF7SB_Blocklist::get_setting( 'message' ) );
				break;
			}
		}
		return $result;
	}

	public static function validate_text( $result, $tag ) {
		$value = self::posted_value( $tag );
		if ( null === $value || '' === $value ) {
			return $result;
		}

		$list    = CF7SB_Blocklist::get();
		$needles = array_merge( $list['domains'], $list['emails'], $list['keywords'] );

		foreach ( $needles as $needle ) {
			if ( false !== stripos( $value, $needle ) ) {
				$result->invalidate( $tag, CF7SB_Blocklist::get_setting( 'message' ) );
				break;
			}
		}
		return $result;
	}
}
