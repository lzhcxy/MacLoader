#!/usr/bin/env bash
# =============================================================================
#  verify.sh — 构建本源码，核对产物是否与参考 MacLoader.app 逐字节相同
#
#  用法:  ./tools/verify.sh [参考.app 路径]
#         默认参考: /Users/sys0ne/Downloads/MacLoader.app
# =============================================================================
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
REF="${1:-/Users/sys0ne/Downloads/MacLoader.app}"
NEW="$ROOT/src-tauri/target/release/bundle/macos/MacLoader.app"

export PATH="$HOME/.cargo/bin:/opt/homebrew/bin:/usr/local/bin:$PATH"

echo "==> 构建 (cargo tauri build)"
( cd "$ROOT/src-tauri" && cargo tauri build >/dev/null )

[ -d "$NEW" ] || { echo "✗ 未生成 $NEW"; exit 1; }

echo "==> 核对 (参考: $REF)"
fail=0
while IFS= read -r f; do
  a=$(shasum -a 256 "$REF/$f" | cut -d' ' -f1)
  b=$(shasum -a 256 "$NEW/$f" 2>/dev/null | cut -d' ' -f1 || true)
  if [ "$a" = "$b" ]; then
    echo "  OK   $f"
  else
    echo "  DIFF $f"
    echo "       ref=$a"
    echo "       new=${b:-<缺失>}"
    fail=1
  fi
done < <( cd "$REF" && find . -type f | sort )

if [ "$fail" = 0 ]; then
  echo "==> ✅ 逐字节一致"
else
  echo "==> ❌ 存在差异"
  exit 1
fi
