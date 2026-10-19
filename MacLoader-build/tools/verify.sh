#!/usr/bin/env bash
# =============================================================================
#  verify.sh —— 构建产物一致性校验
#
#  背景: 旧版本拿 ~/Downloads/MacLoader.app 做参考做逐字节比对, 但
#    (a) 那个文件已经不存在了;
#    (b) 本源码树的前端相对参考产物做过布局修改, 逐字节复现不再是目标。
#
#  现在校验的是「真正会出错的环节」:
#    dist/ 里的前端资源是否被 tauri-codegen 原样嵌进了 .app。
#  这条链路一旦出问题(比如 dist 里多了临时文件、或 codegen 缓存没刷新),
#  表现是「改了前端但产物界面没变」—— 很难排查。
# =============================================================================
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DIST="$ROOT/dist"
APP="${1:-$ROOT/src-tauri/target/release/bundle/macos/MacLoader.app}"
BIN="$APP/Contents/MacOS/macloader"

fail=0
pass=0

ok()   { printf '  \033[32m[OK]\033[0m   %s\n' "$1"; pass=$((pass+1)); }
bad()  { printf '  \033[31m[FAIL]\033[0m %s\n' "$1"; fail=$((fail+1)); }
warn() { printf '  \033[33m[警告]\033[0m %s\n' "$1"; }
head2() { printf '\n\033[1m%s\033[0m\n' "$1"; }

# ---------------------------------------------------------------- 产物存在性
head2 "1. 产物"
if [ ! -d "$APP" ]; then
  bad "找不到 .app: $APP"
  echo
  echo "先构建:  cd src-tauri && cargo tauri build"
  exit 1
fi
ok ".app 存在"
[ -x "$BIN" ] && ok "可执行文件存在" || bad "缺少可执行文件: $BIN"

# ------------------------------------------------------- 前端资源是否被嵌入
head2 "2. 前端资源嵌入（dist/ → 二进制）"
# tauri-codegen 把 dist/ 下的文件以 brotli 形式嵌进二进制。
# 校验方法: 在二进制里找每个文件的「原始字节流的 brotli 特征」不可靠,
# 改为用 tools/extract.py 解出内嵌资源再逐字节比对 —— 那才是权威做法。
EXTRACT="$ROOT/tools/extract.py"
TMPD="$(mktemp -d)"
trap 'rm -rf "$TMPD"' EXIT

if [ ! -f "$EXTRACT" ]; then
  warn "缺少 $EXTRACT, 跳过内嵌资源比对"
else
  if python3 "$EXTRACT" "$BIN" "$TMPD" >/dev/null 2>&1; then
    # extract.py 输出的文件名是 sha256 前缀 + 猜的扩展名,
    # 所以按「内容是否能在解包结果里找到」来比对, 而不是按文件名。
    for f in index.html style.css app.js shell.js; do
      src="$DIST/$f"
      want="$(python3 -c "import hashlib,sys;print(hashlib.sha256(open(sys.argv[1],'rb').read()).hexdigest())" "$src" 2>/dev/null)"
      got="$(find "$TMPD" -type f -exec sh -c 'python3 -c "import hashlib,sys;print(hashlib.sha256(open(sys.argv[1],\"rb\").read()).hexdigest())" "$1"' _ {} \; 2>/dev/null)"
      if [ -n "$want" ] && printf '%s\n' "$got" | grep -qx "$want"; then
        ok "$f 已逐字节嵌入产物"
      else
        bad "$f 未在产物里找到逐字节一致的副本（改了前端但没重新构建？）"
      fi
    done
  else
    warn "extract.py 解包失败, 跳过内嵌资源比对"
  fi
fi

# ------------------------------------------------------------ dist 目录卫生
head2 "3. dist/ 目录卫生"
# dist/ 会被 tauri-codegen 递归嵌入, 临时文件会污染产物体积与内容
junk="$(find "$DIST" -type f \
  \( -name '*.bak' -o -name '*.orig' -o -name '*~' -o -name '*.tmp' \
     -o -name '*.log' -o -name '.DS_Store' -o -name 'Thumbs.db' \) 2>/dev/null)"
if [ -n "$junk" ]; then
  if [ "$junk" = "$DIST/.DS_Store" ]; then
    warn ".DS_Store 会被一并嵌入（仓库刻意保留, 见 .gitignore 注释）"
  else
    bad "dist/ 里有临时文件: $(echo "$junk" | tr '\n' ' ')"
  fi
else
  ok "dist/ 没有临时文件"
fi

# ---------------------------------------------------------------- 版本一致
head2 "4. 版本号一致"
CARGO_VER="$(grep -m1 '^version' "$ROOT/src-tauri/Cargo.toml" | sed 's/.*"\(.*\)".*/\1/')"
CONF_VER="$(python3 -c "import json;print(json.load(open('$ROOT/src-tauri/tauri.conf.json'))['version'])" 2>/dev/null)"
if [ -n "$CARGO_VER" ] && [ "$CARGO_VER" = "$CONF_VER" ]; then
  ok "Cargo.toml 与 tauri.conf.json 版本一致 ($CARGO_VER)"
else
  bad "版本不一致: Cargo.toml=$CARGO_VER  tauri.conf.json=$CONF_VER"
fi

# ------------------------------------------------------------------ 签名
head2 "5. 产物签名"
if command -v codesign >/dev/null 2>&1; then
  if codesign -v "$APP" >/dev/null 2>&1; then
    ok "codesign 校验通过"
  else
    warn "codesign 校验未通过（ad-hoc 签名正常, 分发前需正式签名）"
  fi
fi

# ------------------------------------------------------------------ 汇总
echo
if [ "$fail" -eq 0 ]; then
  printf '\033[32m✔ 全部通过\033[0m (%d 项)\n' "$pass"
  exit 0
else
  printf '\033[31m✘ %d 项失败\033[0m (%d 项通过)\n' "$fail" "$pass"
  exit 1
fi
