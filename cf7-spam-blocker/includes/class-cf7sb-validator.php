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
		add_filter( 'wpcf7_feedback_response', array( __CLASS__, 'mark_feedback_response' ), 10, 2 );
		add_action( 'wp_footer', array( __CLASS__, 'print_frontend_script' ), 20 );
	}

	/**
	 * AJAXの応答に自プラグインのブロック印を付ける（フロント側でフォームを消すために使う）。
	 */
	public static function mark_feedback_response( $response, $result = array() ) {
		if ( self::$blocked && is_array( $response ) ) {
			$response['cf7sb_blocked'] = true;
		}
		return $response;
	}

	/**
	 * ブロック時にフォームを消し、入力値をクリアして拒否メッセージだけを残すスクリプト。
	 * ブラウザバックで入力内容が復元されないよう、送信時点で値を空にする。
	 */
	public static function print_frontend_script() {
		if ( ! function_exists( 'wpcf7_enqueue_scripts' ) ) {
			return;
		}
		?>
<style id="cf7sb-blocked-style">
.cf7sb-blocked-notice{border:2px solid #d63638;border-radius:4px;background:#fff;color:#d63638;
padding:1.2em 1.4em;margin:1em 0;font-weight:700;line-height:1.6;text-align:center;}
</style>
<script id="cf7sb-blocked-script">
( function () {
	function clearFields( form ) {
		var fields = form.querySelectorAll( 'input, textarea, select' );
		Array.prototype.forEach.call( fields, function ( el ) {
			var type = ( el.type || '' ).toLowerCase();
			if ( 'hidden' === type || 'submit' === type || 'button' === type ) {
				return;
			}
			if ( 'checkbox' === type || 'radio' === type ) {
				el.checked = false;
			} else if ( 'SELECT' === el.tagName ) {
				el.selectedIndex = 0;
			} else {
				el.value = '';
			}
			el.setAttribute( 'autocomplete', 'off' );
		} );
	}

	document.addEventListener( 'wpcf7submit', function ( event ) {
		var res = event.detail && event.detail.apiResponse;
		if ( ! res || ! res.cf7sb_blocked ) {
			return;
		}

		var form = event.target.tagName === 'FORM'
			? event.target
			: event.target.querySelector( 'form.wpcf7-form' );
		if ( ! form ) {
			return;
		}

		// ブラウザバックで復元されないよう、まず入力値を消す
		clearFields( form );

		var notice = document.createElement( 'div' );
		notice.className = 'cf7sb-blocked-notice';
		notice.setAttribute( 'role', 'alert' );
		notice.textContent = res.message || '';

		// フォームの中身をすべて取り除き、メッセージだけを残す
		var wrapper = form.closest( '.wpcf7' ) || form.parentNode;
		form.parentNode.removeChild( form );
		wrapper.innerHTML = '';
		wrapper.appendChild( notice );
	}, false );
} )();
</script>
		<?php
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
