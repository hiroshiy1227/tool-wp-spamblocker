# CF7 Spam Blocker

Contact Form 7 用の迷惑メールブロッカー。拒否ドメイン・拒否文字列のブロックリストを中央サーバーに置き、複数サイトで共有します。WordPress.org 非登録の自前配布で、プラグイン本体の更新は GitHub Releases 経由で全サイトに通知されます。

## 構成

```
cf7-spam-blocker/        ← プラグイン本体（各サイトにインストール）
server/blocklist-api.php ← ブロックリスト配信・受付API（自分のサーバー1箇所に設置）
.github/workflows/release.yml ← タグpushでzipビルド＆Release自動作成
build.sh                 ← 手動インストール用zip作成スクリプト
```

## ブロック仕様

- **メール欄** (`email` / `email*`): 拒否ドメインとの完全一致（サブドメイン含む）でブロック
- **テキスト・本文欄** (`text` / `textarea`): 拒否ドメインまたは拒否文字列（会社名など）が含まれていればブロック
- リストは1時間ごとに自動取得（wp-cron）。取得失敗時は前回のリストで動き続けます
- 秘密キーを設定したサイトの管理画面からリストを編集でき、中央サーバーに保存 → 同じリストを参照する全サイトに反映されます

## 初回セットアップ

### 1. GitHubリポジトリ（プラグイン本体の配布・更新用）

1. GitHubの **パブリック** リポジトリ [hiroshiy1227/tool-wpplugin-spamblocker](https://github.com/hiroshiy1227/tool-wpplugin-spamblocker) にこのディレクトリをpush
2. リポジトリを移動・改名した場合は、`cf7-spam-blocker/cf7-spam-blocker.php` ヘッダーの `Update URI:` を新しいリポジトリURLに合わせる

### 2. ブロックリスト中央サーバー（1箇所だけ）

1. `server/blocklist-api.php` を自分のサーバーに設置（例: `https://example.com/cf7sb/blocklist-api.php`）
2. ファイル内の `CF7SB_API_KEY` を長いランダム文字列に変更

   ```bash
   openssl rand -hex 32
   ```

※ ブロックリストは書き込みAPIと秘密キーが必要なため、GitHubではなく自分のサーバーに置きます（リポジトリには含まれません）。

### 3. 各サイトへのインストール

1. `./build.sh` でzip化し、各サイトの「プラグイン → 新規追加 → プラグインのアップロード」からインストール・有効化（初回のみ手動。以降はGitHub経由で更新）
2. 各サイトの「設定 → CF7 Spam Blocker」で以下を設定
   - **ブロックリストURL**: `https://example.com/cf7sb/blocklist-api.php?list=default`
     - `?list=会社A` のようにリスト名を変えると、用途別（会社A用・会社B用・個人用など）に別リストを共有できます
   - **書き込み用秘密キー**: `blocklist-api.php` に設定したキー（編集させたいサイトのみ。空なら閲覧・自動取得のみ）

## リストの編集

どのサイトでも「設定 → CF7 Spam Blocker」で拒否ドメイン・拒否文字列を1行1件で編集し「保存」するだけです。中央サーバーに保存され、同じリストを参照する他サイトには次回の自動取得（最長1時間後）または「今すぐ再取得」で反映されます。

## バージョンアップの出し方（Git経由）

1. コードを修正し、`cf7-spam-blocker/cf7-spam-blocker.php` の `Version:` ヘッダーと `CF7SB_VERSION` 定数を上げる
2. コミットしてタグをpush

   ```bash
   git add -A && git commit -m "v1.1.0"
   git tag v1.1.0
   git push origin main --tags
   ```

→ GitHub Actionsが自動でzipをビルドしてReleaseを作成します（タグとVersionが不一致だと失敗して教えてくれます）。各サイトの管理画面（プラグイン一覧）に更新通知が出て、ワンクリックで更新できます。自動更新を有効にすれば自動適用されます。

更新チェックの結果は最大6時間キャッシュされます。すぐ確認したい場合は各サイトの「ダッシュボード → 更新 → 再確認」。

### 補足

- アップデーターは `Update URI:` がGitHub以外のURLの場合、そのURLを `info.json`（`version` / `package` を持つJSON）として参照する自前サーバー方式でも動作します。
