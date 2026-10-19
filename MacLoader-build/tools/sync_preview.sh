#!/usr/bin/env bash
# =============================================================================
#  sync_preview.sh —— 把 dist/ 同步到 ui-preview/，并补回纯浏览器预览所需的 mock
#
#  为什么需要脚本而不能直接 rsync:
#    dist/index.html 里**不能**有 mock.js（真实 Tauri 构建会加载它，
#    会顶掉真 runtime 的 window.__TAURI__）。
#    而 ui-preview/index.html 里**必须**有 mock.js，否则 window.__TAURI__ 未定义，
#    app.js 第一行 `window.__TAURI__.core` 就抛错 —— 整个脚本挂掉，
#    表现为「预览页所有模块空白、按钮全都没反应」，很容易被误判成布局 bug。
#
#  用法: ./tools/sync_preview.sh
# =============================================================================
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DIST="$ROOT/dist"
PREVIEW="$ROOT/../ui-preview"

if [ ! -d "$DIST" ]; then echo "找不到 $DIST"; exit 1; fi
if [ ! -d "$PREVIEW" ]; then echo "找不到 $PREVIEW"; exit 1; fi

# 1. 同步（保留预览自己的 mock.js）
rsync -a --exclude '.DS_Store' --exclude 'mock.js' "$DIST/" "$PREVIEW/"

# 2. 确保 index.html 引用了 mock.js，且顺序在 app.js 之前
python3 - "$PREVIEW/index.html" <<'PY'
import sys, re
p = sys.argv[1]
s = open(p).read()
mock = '<script src="mock.js"></script>'
if mock not in s:
    # 插到 app.js 之前
    s = s.replace('<script src="app.js"></script>', mock + '\n<script src="app.js"></script>', 1)
    open(p, 'w').write(s)
    print("已注入 mock.js 引用")
else:
    # 已存在，但确认在 app.js 之前
    if s.index(mock) > s.index('<script src="app.js"></script>'):
        s = s.replace(mock, '', 1)
        s = s.replace('<script src="app.js"></script>', mock + '\n<script src="app.js"></script>', 1)
        open(p, 'w').write(s)
        print("已修正 mock.js 顺序")
    else:
        print("mock.js 引用正常")
PY

echo "预览已同步: $PREVIEW"
