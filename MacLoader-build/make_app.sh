#!/usr/bin/env bash
# =============================================================================
#  make_app.sh — 从源码构建 MacLoader.app
#
#  用法:
#     ./make_app.sh              # 产物在 ./build/MacLoader.app
#     ./make_app.sh /输出/目录
#
#  目录结构要求:
#     <源码根>/
#       ├── src-tauri/           Rust 工程 (Cargo.toml / tauri.conf.json / src / assets ...)
#       └── dist/                前端静态页 (index.html / style.css / app.js / logo.png)
# =============================================================================
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
OUT="${1:-$ROOT/build}"

NAME="MacLoader"
EXEC="MacLoader"

export PATH="$HOME/.cargo/bin:/opt/homebrew/bin:/usr/local/bin:$PATH"

# ------------------------------- 环境检查 -------------------------------
echo "==> 检查环境"
if ! command -v cargo >/dev/null 2>&1; then
  echo "  ✗ 未找到 cargo。先安装 Rust:"
  echo "      curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh"
  echo "      source \"\$HOME/.cargo/env\""
  exit 1
fi
echo "  ✓ cargo $(cargo --version | awk '{print $2}')"

if command -v x86_64-w64-mingw32-g++ >/dev/null 2>&1; then
  echo "  ✓ mingw-w64 (交叉编译 Windows exe 用)"
else
  echo "  ⚠ 未找到 mingw-w64 —— app 能构建，但生成不了 exe"
  echo "      brew install mingw-w64"
fi

if command -v osslsigncode >/dev/null 2>&1; then
  echo "  ✓ osslsigncode (签名用)"
else
  echo "  ⚠ 未找到 osslsigncode —— 签名功能会跳过  (brew install osslsigncode)"
fi

[ -d "$ROOT/src-tauri" ] || { echo "  ✗ 缺少 src-tauri/ 目录"; exit 1; }
[ -d "$ROOT/dist" ]      || { echo "  ✗ 缺少 dist/ 目录"; exit 1; }

# ------------------------------- 编译 Rust -------------------------------
# 必须用 `cargo tauri build`, 不能只用 `cargo build`:
# 裸 cargo build 不会把 dist/ 里的前端嵌入二进制 —— 生成的 app 打开是空页面。
# (这个坑踩过一次: 后端改了但界面没变, 排查了很久才发现前端根本没进去。)
echo "==> 编译 Rust (release)"
if command -v cargo-tauri >/dev/null 2>&1; then
  (
    cd "$ROOT/src-tauri"
    cargo tauri build --no-bundle
  )
  BIN="$ROOT/src-tauri/target/release/macloader"
else
  echo "  ⚠ 未安装 cargo-tauri —— 退回 cargo build, 前端不会被嵌入!"
  echo "    安装: cargo install tauri-cli --version '^2' --locked"
  (
    cd "$ROOT/src-tauri"
    cargo build --release
  )
  BIN="$ROOT/src-tauri/target/release/macloader"
fi
[ -f "$BIN" ] || { echo "  ✗ 编译产物不存在: $BIN"; exit 1; }
echo "  ✓ $BIN"

# ------------------------------- 组装 .app -------------------------------
echo "==> 组装 $NAME.app"
APP="$OUT/$NAME.app"
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"

cp "$BIN" "$APP/Contents/MacOS/$EXEC"
chmod +x "$APP/Contents/MacOS/$EXEC"

ICNS="$ROOT/src-tauri/icons/AppIcon.icns"
if [ -f "$ICNS" ]; then
  cp "$ICNS" "$APP/Contents/Resources/AppIcon.icns"
else
  echo "  ⚠ 未找到 AppIcon.icns，使用系统默认图标"
fi

cat > "$APP/Contents/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>CFBundleName</key>                <string>MacLoader</string>
	<key>CFBundleDisplayName</key>         <string>MacLoader</string>
	<key>CFBundleExecutable</key>          <string>MacLoader</string>
	<key>CFBundleIdentifier</key>          <string>com.macloader.gui</string>
	<key>CFBundleInfoDictionaryVersion</key><string>6.0</string>
	<key>CFBundlePackageType</key>         <string>APPL</string>
	<key>CFBundleShortVersionString</key>  <string>1.1.0</string>
	<key>CFBundleVersion</key>             <string>1.1.0</string>
	<key>CFBundleIconFile</key>            <string>AppIcon</string>
	<key>LSMinimumSystemVersion</key>      <string>11.0</string>
	<key>NSHighResolutionCapable</key>     <true/>
	<key>LSApplicationCategoryType</key>   <string>public.app-category.developer-tools</string>
</dict>
</plist>
PLIST
echo "  ✓ Info.plist"

# ------------------------------- 签名 .app -------------------------------
echo "==> 临时签名 (ad-hoc)"
codesign --force --deep --sign - "$APP" 2>&1 | sed 's/^/  /'
xattr -cr "$APP" 2>/dev/null || true

# ------------------------------- 收尾 -------------------------------
SIZE=$(du -sh "$APP" | awk '{print $1}')
echo
echo "=============================================="
echo "  构建完成: $APP"
echo "  体积:     $SIZE"
echo "  双击即可运行；若提示「无法验证开发者」：右键 → 打开"
echo "=============================================="
