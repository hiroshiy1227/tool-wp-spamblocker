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

	/** ブロック理由（rule/matched/field/excerpt）。ログ記録に使う */
	private static $block_info = null;

	/** ログ記録済みか（1リクエストにつき1回だけ記録する） */
	private static $logged = false;

	public static function init() {
		add_filter( 'wpcf7_spam', array( __CLASS__, 'spam_check' ), 10, 2 );
		add_filter( 'wpcf7_display_message', array( __CLASS__, 'filter_display_message' ), 10, 2 );
		add_filter( 'wpcf7_feedback_response', array( __CLASS__, 'mark_feedback_response' ), 10, 2 );
		add_action( 'wp_footer', array( __CLASS__, 'print_frontend_script' ), 20 );
	}

	/**
	 * 応答を最終的に上書きしてブロックを確定させる。
	 *
	 * CF7は「入力チェックを通過した送信」しかスパム判定にかけない（submission.php の proceed）。
	 * そのため必須項目が空のままだと validation_failed で止まり、拒否条件の判定が行われない。
	 * ここで改めて判定し、入力チェックの結果にかかわらずブロックを適用する。
	 */
	public static function mark_feedback_response( $response, $result = array() ) {
		if ( ! is_array( $response ) ) {
			return $response;
		}

		if ( ! self::$blocked && class_exists( 'WPCF7_Submission' ) ) {
			$submission = WPCF7_Submission::get_instance();
			if ( $submission && self::submission_blocked( $submission ) ) {
				self::$blocked = true;
				self::record_block( $submission );
			}
		}

		if ( self::$blocked ) {
			$message = CF7SB_Blocklist::get_message();

			$response['status']        = 'spam';
			$response['cf7sb_blocked'] = true;
			if ( '' !== $message ) {
				$response['message'] = $message;
			}
			// どの項目が原因かを伝えないよう、フィールド単位のエラーは返さない
			unset( $response['invalid_fields'] );
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

		// スクロール位置をページ最上部に戻す。
		// それでもメッセージが画面外になる場合は、メッセージ自体を画面内に入れる。
		window.scrollTo( 0, 0 );
		window.requestAnimationFrame( function () {
			var rect = notice.getBoundingClientRect();
			var height = window.innerHeight || document.documentElement.clientHeight;
			if ( rect.bottom < 0 || rect.top > height ) {
				notice.scrollIntoView( { block: 'center' } );
			}
		} );
	}, false );
} )();
</script>
		<?php
	}

	/**
	 * メール欄の値がブロック対象なら理由を返す（拒否メールアドレス完全一致／拒否ドメイン）。
	 *
	 * @return array{rule: string, matched: string}|null
	 */
	public static function detect_email_block( $value ) {
		$value = strtolower( trim( (string) $value ) );
		if ( '' === $value ) {
			return null;
		}
		$list = CF7SB_Blocklist::get();

		foreach ( $list['emails'] as $email ) {
			if ( strtolower( trim( $email ) ) === $value ) {
				return array( 'rule' => 'email', 'matched' => $email );
			}
		}
		foreach ( $list['domains'] as $domain ) {
			// 完全一致＋サブドメインも対象
			if ( preg_match( '/@([a-z0-9\-]+\.)*' . preg_quote( strtolower( $domain ), '/' ) . '$/i', $value ) ) {
				return array( 'rule' => 'domain', 'matched' => $domain );
			}
		}
		return null;
	}

	public static function is_blocked_email_value( $value ) {
		return null !== self::detect_email_block( $value );
	}

	/**
	 * テキスト/本文欄の値がブロック対象なら理由を返す
	 * （拒否ドメイン・拒否メールアドレス・拒否文字列を含む／相互リンク／拒否パターン）。
	 *
	 * @return array{rule: string, matched: string}|null
	 */
	public static function detect_text_block( $value ) {
		$value = (string) $value;
		if ( '' === $value ) {
			return null;
		}
		$list = CF7SB_Blocklist::get();

		$groups = array(
			'domain'  => $list['domains'],
			'email'   => $list['emails'],
			'keyword' => $list['keywords'],
		);
		foreach ( $groups as $rule => $needles ) {
			foreach ( $needles as $needle ) {
				if ( false !== stripos( $value, $needle ) ) {
					return array( 'rule' => $rule, 'matched' => $needle );
				}
			}
		}
		if ( ! empty( $list['block_link'] ) && self::is_link_exchange_value( $value ) ) {
			return array( 'rule' => 'link', 'matched' => self::link_exchange_score( $value ) . '点' );
		}
		if ( ! empty( $list['block_sales'] ) && self::is_sales_mail_value( $value ) ) {
			return array( 'rule' => 'sales', 'matched' => self::link_exchange_score( $value ) . '点' );
		}
		return self::detect_pattern( $value );
	}

	public static function is_blocked_text_value( $value ) {
		return null !== self::detect_text_block( $value );
	}

	/**
	 * 内蔵フィルターのシグナル定義（判定エンジンと「内蔵ルール」タブの表示で共用）。
	 * genre: link=相互リンクフィルターの核心 / sales=営業メールフィルターの核心 / weak=共通の弱シグナル
	 * 各要素: array( genre, label, points, pattern )。pattern 'url3' はURLが3か所以上あるかの特別判定。
	 */
	public static function filter_signals() {
		return array(
			array( 'link', '依頼の核心語（相互リンク・リンク交換・発リンク・dofollow・相互紹介／送客／掲載・「紹介し合う」・コンテンツ連携／記事連携）', 2,
				'/相互\s*リンク|リンク\s*交換|発リンク|dofollow|相互(に)?(ご)?(紹介|送客|掲載)|(ご)?(紹介|掲載|送客)し(合|あ)|(コンテンツ|記事)連携/iu' ),
			array( 'sales', '一斉配信メールの定型文（「配信停止はこちら」等の解除案内。正当な問い合わせには現れない）', 2,
				'/(配信|メルマガ)の?(停止|解除)(の|を)?ご?希望|(配信|メルマガ)の?(停止|解除)は(こちら|お手数)|配信の?(停止|解除).{0,60}(宛|までご?連絡)/us' ),
			array( 'weak', 'リンク設置の言い回し（リンクを設置／掲載／追加・アンカーテキスト）', 1,
				'/リンク(を|の)?(設置|掲載|追加)|アンカーテキスト/u' ),
			array( 'weak', '本文中のURL', 1, '#https?://\S*#i' ),
			array( 'weak', '多数のURL（本文に3か所以上。一斉送信の営業文の特徴）', 1, 'url3' ),
			array( 'weak', '営業定型の導入句（「突然のご連絡」「唐突なご連絡」等）', 1, '/(突然|唐突)の(ご)?(連絡|メール)/u' ),
			array( 'weak', '検索評価の用語（DR・ドメイン評価・SEO・検索順位・被リンク・nofollow等）', 1,
				'/ドメイン(評価|パワー|レーティング)|(^|[^a-z])DR([^a-z]|$)|SEO|検索順位|サイト集客|被リンク|nofollow/iu' ),
			array( 'weak', '無償オファー（「費用は一切かかりません」等。「かかりませんか？」の質問形は除外）', 1,
				'/費用(は|も|が)?(一切|いっさい)?(かか|掛か)(らず|らない|りません(?!か))|(無料|無償)で(の)?(ご)?(掲載|紹介|案内|リンク)/u' ),
			array( 'weak', 'サイト運営宛ての宛名（「サイト運営ご担当者様」等）', 1,
				'/(サイト|ホームページ|ブログ|メディア)\s*(の)?\s*運営\s*(ご)?担当者?様|運営者様/u' ),
			array( 'weak', '売り込み特有の語（親和性）', 1, '/親和性/u' ),
		);
	}

	/**
	 * 内蔵フィルターの営業メール判定エンジン（相互リンクフィルター・営業メールフィルター共用）。
	 *
	 * 誤ブロックを防ぐため、判定は2段構えにしている。
	 *   (1) 強シグナル（各フィルターの核心・+2点）が無ければ、他が揃ってもそのフィルターはブロックしない
	 *       - 相互リンクフィルターの核心: 相互リンク等の「載せ合う提案」の依頼用語
	 *       - 営業メールフィルターの核心: 「配信停止はこちら」等の一斉配信メールの定型文
	 *         （「配信停止してください」という正当な依頼文は一致しない）
	 *   (2) 核心があっても、弱シグナルを合わせて合計3点未満なら通過
	 * 被リンク・nofollow・SEO などは正当な顧客も使う語なので強シグナルにしない。
	 *
	 * @return array{score:int, core_link:bool, core_sales:bool, blocked_link:bool, blocked_sales:bool, rows:array}
	 *         rows: 各シグナルの array{label:string, points:int, max:int, matched:string}
	 *         （ブロックチェッカーの内訳表示と判定本体で共用）
	 */
	public static function filter_breakdown( $value ) {
		$value = (string) $value;

		$signals = self::filter_signals();

		$score      = 0;
		$core_link  = false;
		$core_sales = false;
		$rows       = array();
		foreach ( $signals as $signal ) {
			list( $genre, $label, $points, $pattern ) = $signal;
			$matched = '';
			if ( '' !== $value ) {
				if ( 'url3' === $pattern ) {
					// 正規表現ではなくURLの個数で判定する特別なシグナル
					$url_count = preg_match_all( '#https?://#i', $value );
					if ( $url_count >= 3 ) {
						$matched = 'URL ' . $url_count . 'か所';
					}
				} elseif ( preg_match( $pattern, $value, $m ) ) {
					$matched = $m[0];
				}
				if ( '' !== $matched ) {
					$score += $points;
					if ( 'link' === $genre ) {
						$core_link = true;
					} elseif ( 'sales' === $genre ) {
						$core_sales = true;
					}
				}
			}
			$rows[] = array(
				'label'   => $label,
				'points'  => ( '' !== $matched ) ? $points : 0,
				'max'     => $points,
				'matched' => $matched,
			);
		}

		return array(
			'score'         => $score,
			'core_link'     => $core_link,
			'core_sales'    => $core_sales,
			'blocked_link'  => ( $core_link && $score >= 3 ),
			'blocked_sales' => ( $core_sales && $score >= 3 ),
			'rows'          => $rows,
		);
	}

	public static function link_exchange_score( $value ) {
		$breakdown = self::filter_breakdown( $value );
		return $breakdown['score'];
	}

	/** 相互リンクフィルター: リンク設置依頼の営業メールか。 */
	public static function is_link_exchange_value( $value ) {
		$breakdown = self::filter_breakdown( $value );
		return $breakdown['blocked_link'];
	}

	/** 営業メールフィルター: 一斉配信の定型文を含む営業メールか。 */
	public static function is_sales_mail_value( $value ) {
		$breakdown = self::filter_breakdown( $value );
		return $breakdown['blocked_sales'];
	}

	/**
	 * 拒否パターン（正規表現）に一致するなら理由を返す。
	 *
	 * @return array{rule: string, matched: string}|null
	 */
	public static function detect_pattern( $value ) {
		$value = (string) $value;
		if ( '' === $value ) {
			return null;
		}
		$list = CF7SB_Blocklist::get();

		// 内蔵ルール: UUID形式の管理番号（設定でON/OFF可・全サイト共通）
		if ( ! empty( $list['block_uuid'] )
			&& 1 === @preg_match( CF7SB_Blocklist::wrap_pattern( CF7SB_Blocklist::UUID_PATTERN ), $value ) ) {
			return array( 'rule' => 'uuid', 'matched' => 'UUID形式の管理番号' );
		}

		foreach ( $list['patterns'] as $pattern ) {
			if ( 1 === @preg_match( CF7SB_Blocklist::wrap_pattern( $pattern ), $value ) ) {
				return array( 'rule' => 'pattern', 'matched' => $pattern );
			}
		}
		return null;
	}

	public static function matches_pattern( $value ) {
		return null !== self::detect_pattern( $value );
	}

	/**
	 * 送信データ全体をチェックしてブロック対象か判定する。
	 * ブロックする場合は、理由・該当値・該当項目をログ用に記録する。
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
			if ( ! in_array( $tag->basetype, array( 'email', 'text', 'textarea', 'url', 'tel' ), true ) ) {
				continue;
			}
			$value = isset( $data[ $tag->name ] ) ? $data[ $tag->name ] : '';
			if ( is_array( $value ) ) {
				$value = implode( ' ', $value );
			}

			$hit = ( 'email' === $tag->basetype )
				? ( self::detect_email_block( $value ) ?: self::detect_pattern( $value ) )
				: self::detect_text_block( $value );

			if ( $hit ) {
				self::$block_info = array(
					'rule'    => $hit['rule'],
					'matched' => $hit['matched'],
					'field'   => $tag->name,
					'excerpt' => $value,
				);
				return true;
			}
		}
		return false;
	}

	/**
	 * ブロックした送信を中央サーバーのログに記録する（1リクエストにつき1回）。
	 */
	private static function record_block( $submission ) {
		if ( self::$logged || ! self::$block_info || ! $submission ) {
			return;
		}
		self::$logged = true;

		$form  = method_exists( $submission, 'get_contact_form' ) ? $submission->get_contact_form() : null;
		$data  = method_exists( $submission, 'get_posted_data' ) ? $submission->get_posted_data() : array();
		$email = '';

		if ( $form && is_array( $data ) ) {
			foreach ( $form->scan_form_tags() as $tag ) {
				if ( 'email' === $tag->basetype && ! empty( $data[ $tag->name ] ) ) {
					$email = is_array( $data[ $tag->name ] ) ? reset( $data[ $tag->name ] ) : $data[ $tag->name ];
					break;
				}
			}
		}

		CF7SB_Blocklist::log_block( array(
			'rule'    => self::$block_info['rule'],
			'matched' => self::$block_info['matched'],
			'field'   => self::$block_info['field'],
			'excerpt' => self::$block_info['excerpt'],
			'email'   => $email,
			'form'    => $form ? $form->title() : '',
			'ip'      => method_exists( $submission, 'get_meta' ) ? (string) $submission->get_meta( 'remote_ip' ) : '',
		) );
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
			self::record_block( $submission );
			return true;
		}
		return $spam;
	}

	/**
	 * 自プラグインがブロックした場合のみ、フォーム全体のメッセージを差し替える。
	 */
	public static function filter_display_message( $message, $status = '' ) {
		if ( self::$blocked && 'spam' === $status ) {
			$custom = CF7SB_Blocklist::get_message();
			if ( '' !== $custom ) {
				return $custom;
			}
		}
		return $message;
	}
}
