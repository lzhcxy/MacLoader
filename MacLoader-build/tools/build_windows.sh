#!/usr/bin/env bash
# =============================================================================
#  build_windows.sh —— 从 macOS 交叉编译 Windows 版（WinLoader.exe）
#
#  用法: ./tools/build_windows.sh
#  产物: dist-windows/WinLoader.exe
#
#  前置:
#    rustup target add x86_64-pc-windows-gnu
#    （首次运行会自动添加）
#
#  说明:
#    Tauri 官方标注交叉编译为 experimental，但对本项目够用：
#    产出的是合法的 PE32+ GUI 可执行文件，前端资源已 brotli 嵌入。
#    NSIS 安装器需要本机 makensis（brew install nsis），未安装时跳过，
#    直接用绿色版 exe 即可。
# =============================================================================
set -euo pipefail

cd "$(dirname "$0")/.."

TARGET="x86_64-pc-windows-gnu"
OUT_DIR="dist-windows"
PRODUCT="WinLoader.exe"

echo "==> 1/4 检查 target"
if ! rustup target list --installed | grep -q "$TARGET"; then
  echo "    添加 $TARGET ..."
  rustup target add "$TARGET"
else
  echo "    $TARGET 已安装"
fi

echo "==> 2/4 检查 Windows 资源图标"
if [[ ! -f src-tauri/icons/icon.ico ]]; then
  echo "    icon.ico 缺失，从 icon.png 生成 ..."
  python3 - <<'PY'
import struct, subprocess, os
src = 'src-tauri/icons/icon.png'
tmp = '/tmp/_mkico'; os.makedirs(tmp, exist_ok=True)
pngs = []
for s in (16, 32, 48, 64, 128, 256):
    dst = f'{tmp}/s{s}.png'
    if subprocess.run(['sips', '-z', str(s), str(s), src, '--out', dst],
                      capture_output=True).returncode != 0:
        continue
    d = open(dst, 'rb').read()
    if len(d) > 8 and d[1:4] == b'PNG':
        pngs.append((s, d))
if not pngs:
    raise SystemExit('图标生成失败')
n = len(pngs)
out = bytearray(struct.pack('<HHH', 0, 1, n))
off = 6 + 16 * n
for s, d in pngs:
    b = 0 if s >= 256 else s
    out += bytes([b, b, 0, 0]) + struct.pack('<HH', 1, 32) + struct.pack('<II', len(d), off)
    off += len(d)
for _, d in pngs:
    out += d
open('src-tauri/icons/icon.ico', 'wb').write(bytes(out))
print(f'    icon.ico: {len(out)} bytes, {n} 个尺寸')
PY
else
  echo "    icon.ico 已存在"
fi

echo "==> 3/4 交叉编译 (release)"
cargo build --release --target "$TARGET" --manifest-path src-tauri/Cargo.toml

echo "==> 4/4 产出绿色版"
mkdir -p "$OUT_DIR"
cp "src-tauri/target/$TARGET/release/macloader.exe" "$OUT_DIR/$PRODUCT"

echo
echo "✔ 完成: $OUT_DIR/$PRODUCT"
ls -lh "$OUT_DIR/$PRODUCT"
echo
echo "提示: NSIS 安装器需要 makensis（brew install nsis）。"
echo "      未安装时直接用上面的绿色版 exe 即可。"
