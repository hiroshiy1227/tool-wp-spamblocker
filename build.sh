#!/bin/bash
# 配布用zipを作成する。
# 使い方: ./build.sh
# 出力: dist/cf7-spam-blocker-<version>.zip

set -euo pipefail
cd "$(dirname "$0")"

VERSION=$(grep -m1 "Version:" cf7-spam-blocker/cf7-spam-blocker.php | sed 's/.*Version:[[:space:]]*//' | tr -d ' ')
OUT="dist/cf7-spam-blocker-${VERSION}.zip"

mkdir -p dist
rm -f "$OUT"
zip -r "$OUT" cf7-spam-blocker -x "*.DS_Store" -x "*/.git/*"

echo ""
echo "作成しました: $OUT"
echo ""
echo "リリースは通常タグpushだけでOK（GitHub Actionsが自動でzip作成＆Release）:"
echo "  git tag v${VERSION} && git push origin main --tags"
echo "このzipは手動インストール・手動Release用です。"
