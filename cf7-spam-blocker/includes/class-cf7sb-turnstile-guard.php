<?php
/**
 * Turnstile（Cloudflare のロボット確認）による送信失敗を防ぐ。
 *
 * CF7 の Turnstile 連携では、確認の値（トークン）が空・期限切れ（約5分）・使用済みのまま送ると
 * スパム判定になり、利用者には「メッセージの送信に失敗しました」とだけ表示される。
 * 見えない形（Invisible）のウィジェットでは、利用者の側で直す手段がない。
 *
 * ・送信の直前：確認の値が空か4分より古ければ、取り直してから送る
 * ・スパム判定になったら：確認を取り直して1回だけ自動で送り直す
 * ・Turnstile の検証に失敗した件数・最近の記録を残す（オプション cf7sb_turnstile_log）
 *
 * 無効にするとき：add_filter( 'cf7sb_turnstile_guard', '__return_false' );
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class CF7SB_Turnstile_Guard {

	const LOG_OPTION = 'cf7sb_turnstile_log';
	const LOG_MAX    = 50;

	public static function init() {
		add_action( 'wp_footer', array( __CLASS__, 'print_script' ), 30 );
		add_action( 'wpcf7_submit', array( __CLASS__, 'record' ), 99, 2 );
	}

	private static function active() {
		if ( ! apply_filters( 'cf7sb_turnstile_guard', true ) ) {
			return false;
		}
		return class_exists( 'WPCF7_Turnstile' ) && WPCF7_Turnstile::get_instance()->is_active();
	}

	/**
	 * Turnstile の検証に失敗した送信を記録する（自動の送り直しで救えたかは、直後の成功の有無で分かる）。
	 */
	public static function record( $contact_form, $result ) {
		if ( ! self::active() || ! class_exists( 'WPCF7_Submission' ) ) {
			return;
		}
		$status = isset( $result['status'] ) ? $result['status'] : '';
		$sub    = WPCF7_Submission::get_instance();
		$ts     = false;
		if ( 'spam' === $status && $sub ) {
			foreach ( (array) $sub->get_spam_log() as $row ) {
				if ( isset( $row['agent'] ) && 'turnstile' === $row['agent'] ) {
					$ts = true;
				}
			}
		}
		$log = get_option( self::LOG_OPTION, array() );
		if ( ! is_array( $log ) ) {
			$log = array();
		}
		if ( ! isset( $log['count'] ) ) {
			$log = array( 'count' => 0, 'since' => current_time( 'mysql' ), 'recent' => array() );
		}
		if ( $ts ) {
			$log['count']++;
			$log['recent'][] = array(
				'time'   => current_time( 'mysql' ),
				'form'   => (int) $contact_form->id(),
				'status' => 'turnstile_failed',
				'ua'     => substr( isset( $_SERVER['HTTP_USER_AGENT'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) ) : '', 0, 160 ),
			);
		} elseif ( 'mail_sent' === $status && ! empty( $log['recent'] ) ) {
			// 直前（2分以内）に同じフォームで Turnstile が失敗していれば、送り直しで救えた印を付ける
			$last = end( $log['recent'] );
			$key  = key( $log['recent'] );
			if ( 'turnstile_failed' === $last['status'] && (int) $last['form'] === (int) $contact_form->id()
				&& strtotime( current_time( 'mysql' ) ) - strtotime( $last['time'] ) <= 120 ) {
				$log['recent'][ $key ]['status'] = 'recovered';
			} else {
				return;
			}
		} else {
			return;
		}
		$log['recent'] = array_slice( $log['recent'], -self::LOG_MAX );
		update_option( self::LOG_OPTION, $log, false );
	}

	public static function print_script() {
		if ( ! self::active() ) {
			return;
		}
		?>
<script id="cf7sb-turnstile-guard">
(function () {
	if (window.cf7sbTsGuard) return;
	window.cf7sbTsGuard = 1;
	var MAX_AGE = 240000; // 4分より古い確認の値は取り直す（期限は約5分）
	var WAIT = 15000;     // 取り直しを待つ最長の時間
	var store = [];
	function st(f) {
		for (var k = 0; k < store.length; k++) if (store[k].f === f) return store[k];
		var s = { f: f, last: '', at: 0, retried: false, auto: false };
		store.push(s);
		return s;
	}
	function input(f) { return f.querySelector('[name="_wpcf7_turnstile_response"]'); }
	function formOf(t) {
		if (!t || !t.querySelector) return null;
		return t.matches && t.matches('form.wpcf7-form') ? t : t.querySelector('form.wpcf7-form');
	}
	setInterval(function () {
		var fs = document.querySelectorAll('form.wpcf7-form');
		for (var k = 0; k < fs.length; k++) {
			var i = input(fs[k]);
			if (!i) continue;
			var s = st(fs[k]);
			if (i.value !== s.last) { s.last = i.value; s.at = i.value ? Date.now() : 0; }
		}
	}, 500);
	function busy(f, on) {
		f.classList.toggle('cf7sb-ts-wait', on);
		var b = f.querySelector('input[type="submit"], button[type="submit"]');
		if (!b) return;
		if (on) {
			if (b.dataset.cf7sbLabel === undefined) b.dataset.cf7sbLabel = b.tagName === 'INPUT' ? b.value : b.textContent;
			if (b.tagName === 'INPUT') b.value = '送信の準備をしています…'; else b.textContent = '送信の準備をしています…';
			b.style.opacity = '.7';
		} else if (b.dataset.cf7sbLabel !== undefined) {
			if (b.tagName === 'INPUT') b.value = b.dataset.cf7sbLabel; else b.textContent = b.dataset.cf7sbLabel;
			b.style.opacity = '';
		}
	}
	function refresh(f, cb) {
		var i = input(f), w = f.querySelector('.cf-turnstile');
		if (!i || !w || !window.turnstile) { cb(); return; }
		var old = i.value, t0 = Date.now();
		try { window.turnstile.reset(w); } catch (e) {}
		var t = setInterval(function () {
			var v = input(f).value;
			if ((v && v !== old) || Date.now() - t0 > WAIT) { clearInterval(t); cb(); }
		}, 250);
	}
	function send(f, submitter) {
		st(f).auto = true;
		busy(f, false);
		if (f.requestSubmit) {
			try { submitter ? f.requestSubmit(submitter) : f.requestSubmit(); return; } catch (e) {}
		}
		if (window.wpcf7 && window.wpcf7.submit) { st(f).auto = false; window.wpcf7.submit(f); }
	}
	// 送信の直前：確認の値が空・古いときは取り直してから送る（CF7 より先に受け取るため、文書全体の捕捉で聞く）
	document.addEventListener('submit', function (e) {
		var f = e.target;
		if (!f || !f.matches || !f.matches('form.wpcf7-form') || !input(f)) return;
		var s = st(f);
		if (s.auto) { s.auto = false; return; }
		s.retried = false; // 利用者が押した送信
		var i = input(f);
		if (i.value && s.at && Date.now() - s.at < MAX_AGE) return;
		e.preventDefault();
		e.stopImmediatePropagation();
		var submitter = e.submitter || null;
		busy(f, true);
		refresh(f, function () { send(f, submitter); });
	}, true);
	// スパム判定になったら：確認を取り直して1回だけ自動で送り直す
	document.addEventListener('wpcf7spam', function (e) {
		var f = formOf(e.target);
		if (!f || !input(f)) return;
		if (e.detail && e.detail.apiResponse && e.detail.apiResponse.cf7sb_blocked) return; // ブロックリストによる拒否は送り直さない
		var s = st(f);
		if (s.retried) return;
		s.retried = true;
		var out = f.querySelector('.wpcf7-response-output');
		setTimeout(function () { if (out) out.textContent = '送信しています。そのままお待ちください…'; }, 0);
		busy(f, true);
		setTimeout(function () { refresh(f, function () { send(f, null); }); }, 300);
	});
})();
</script>
		<?php
	}
}
