#!/usr/bin/env python3
# =============================================================================
#  extract.py — 从 MacLoader.app 的 Mach-O 里还原可还原的源码 / 资源
#
#  Tauri 打包时对前端的处理方式（本工具据此还原）：
#    * assets/loader.cpp   → include_str!  **明文**嵌入          → 可 100% 还原
#    * dist/*.png 等已是压缩格式、brotli 压不动的 → **原样**嵌入  → 可按魔数还原
#    * dist/*.html/.css/.js 及可压缩的 png → brotli 压缩后嵌入
#                             （单个流无魔数，见下）              → 见 build/OUT_DIR
#    * Rust 后端 (main.rs)  → 编译成机器码，**无法**还原源码；
#                             用 src-tauri/ 中与参考产物完全一致、
#                             可复现出同一二进制的源码即可。
#
#  用法:
#     python3 extract.py <MacLoader.app> <输出目录>
#
#  说明: “可压缩”资源（html/css/js + 部分 png）以 brotli 流嵌入，无固定魔数，
#        从成品二进制里爆破识别不可靠。要拿到它们的原文：
#          1) 本仓库 dist/ 已是从参考产物逐字节校验过的一致副本；
#          2) 或本地 `cargo tauri build`，资源会以明文落在
#             src-tauri/target/release/build/macloader-*/out/tauri-codegen-assets/
#             每个文件即压缩前原文（brotli -d 可解）。
# =============================================================================
import sys, os, struct, hashlib

PNG_MAGIC = b"\x89PNG\r\n\x1a\n"
ICO_MAGIC = b"\x00\x00\x01\x00"


def sha(b):
    return hashlib.sha256(b).hexdigest()


# ---------------------------------------------------------------- 明文资源
# loader.cpp 结尾锚点：include_str! 的数据**不是** NUL 结尾的，它后面紧挨着
# 下一个字符串字面量，所以不能在 NUL 处截断。用文件真实结尾做锚。
LOADER_TAIL = b"return loader_main(argc, argv);\n}\n#endif\n"


def extract_loader_cpp(blob):
    """loader.cpp 用 include_str! 明文嵌入：首锚点到尾锚点。"""
    start = blob.find(b"/*\n * loader.cpp")
    if start < 0:
        return None
    end = blob.find(LOADER_TAIL, start)
    if end < 0:                       # 兜底：找不到尾锚就退到 NUL
        end = blob.find(b"\x00", start)
    else:
        end += len(LOADER_TAIL)
    return blob[start:end]


def png_len(blob, off):
    """从 PNG 魔数处解析到 IEND，返回整段长度；失败返回 None。"""
    if blob[off:off + 8] != PNG_MAGIC:
        return None
    p = off + 8
    n = len(blob)
    while p + 8 <= n:
        ln = struct.unpack(">I", blob[p:p + 4])[0]
        typ = blob[p + 4:p + 8]
        if ln > 50_000_000:
            return None
        p += 12 + ln
        if typ == b"IEND":
            return p - off
    return None


def scan_raw_pngs(blob):
    """回捞原样嵌入的 PNG（按魔数 + 完整 IEND 校验）。"""
    out = []
    i = 0
    while True:
        i = blob.find(PNG_MAGIC, i)
        if i < 0:
            break
        L = png_len(blob, i)
        if L:
            out.append((i, blob[i:i + L]))
            i += L
        else:
            i += 1
    return out


def scan_raw_icos(blob):
    """回捞原样嵌入的 ICO（含 1..N 个 PNG 帧的容器）。"""
    out = []
    i = 0
    n = len(blob)
    while True:
        i = blob.find(ICO_MAGIC, i)
        if i < 0:
            break
        try:
            cnt = struct.unpack("<H", blob[i + 4:i + 6])[0]
            if 1 <= cnt <= 64:
                off = 6 + 16 * cnt
                end = off
                ok = True
                for k in range(cnt):
                    e = i + 6 + 16 * k
                    sz, o = struct.unpack("<II", blob[e + 8:e + 16])
                    if o < off or i + o + sz > n:
                        ok = False
                        break
                    end = max(end, o + sz)
                if ok and end > 6 + 16 * cnt:
                    out.append((i, blob[i:i + end]))
                    i += end
                    continue
        except Exception:
            pass
        i += 1
    return out


def decompress(blob):
    """tauri-codegen 把可压缩资源以 brotli 流存盘。能解就解，不能解原样返回。

    判断依据不是扩展名而是内容：brotli 流没有魔数，只能试着解。
    """
    try:
        import brotli

        return brotli.decompress(blob)
    except Exception:
        pass
    # brotli 模块没装时退回命令行工具
    import subprocess

    try:
        p = subprocess.run(
            ["brotli", "-d", "-c"], input=blob, capture_output=True, timeout=20
        )
        if p.returncode == 0 and p.stdout:
            return p.stdout
    except Exception:
        pass
    return blob


def scan_codegen_assets(rootdir, blob=None):
    """从 cargo 的 OUT_DIR 里取出**本次构建真正嵌入**的前端资源。

    两个坑，都在这里处理掉：
      * OUT_DIR 按内容 hash 命名，历史构建的文件会残留 —— 只按目录 mtime
        挑一个会挑错（实测：最新的 out 目录里根本没有当前 dist 的内容）。
      * 所以需要第二个判据：把候选资源的**压缩后原始字节**拿去二进制里搜，
        搜得到才是真嵌进去了。压缩字节是 rust 侧产出的，逐字节搜是精确的。
    """
    if not rootdir or not os.path.isdir(rootdir):
        return None
    base = os.path.join(rootdir, "src-tauri", "target", "release", "build")
    if not os.path.isdir(base):
        return None
    dirs = [
        os.path.join(base, d, "out", "tauri-codegen-assets")
        for d in os.listdir(base)
        if d.startswith("macloader-")
        and os.path.isdir(os.path.join(base, d, "out", "tauri-codegen-assets"))
    ]
    if not dirs:
        return None

    out = {}
    for adir in sorted(dirs, key=os.path.getmtime, reverse=True):
        for name in os.listdir(adir):
            p = os.path.join(adir, name)
            if not os.path.isfile(p) or name in out:
                continue
            raw = open(p, "rb").read()
            # 关键判据：压缩后的字节必须真在产物二进制里
            if blob is not None and raw and raw not in blob:
                continue
            out[name] = decompress(raw)
    return out or None


def main():
    if len(sys.argv) < 3:
        print(__doc__)
        sys.exit(1)
    app, outdir = sys.argv[1], sys.argv[2]
    # 参数既可以是 .app 包，也可以是包里的 Mach-O 本身
    if os.path.isfile(app):
        binf = app
    else:
        macos = os.path.join(app, "Contents", "MacOS")
        binf = os.path.join(macos, "macloader")
        if not os.path.isfile(binf):
            binf = os.path.join(macos, sorted(os.listdir(macos))[0])
    blob = open(binf, "rb").read()
    os.makedirs(outdir, exist_ok=True)

    print(f"[i] 二进制  {binf}")
    print(f"[i] size    {len(blob)} bytes")
    print(f"[i] sha256  {sha(blob)}\n")

    lc = extract_loader_cpp(blob)
    if lc:
        open(os.path.join(outdir, "loader.cpp"), "wb").write(lc)
        print(f"[+] loader.cpp            {len(lc):>7} bytes  {sha(lc)[:16]}")
    else:
        print("[-] loader.cpp 未找到")

    seen = set()
    for k, (off, data) in enumerate(scan_raw_pngs(blob)):
        h = sha(data)
        if h in seen:
            continue
        seen.add(h)
        w, hh = struct.unpack(">II", data[16:24])
        name = f"raw-{off:08x}-{w}x{hh}.png"
        open(os.path.join(outdir, name), "wb").write(data)
        print(f"[+] {name:<36} {len(data):>7} bytes  {h[:16]}")

    for off, data in scan_raw_icos(blob):
        h = sha(data)
        if h in seen:
            continue
        seen.add(h)
        name = f"raw-{off:08x}.ico"
        open(os.path.join(outdir, name), "wb").write(data)
        print(f"[+] {name:<36} {len(data):>7} bytes  {h[:16]}")

    # ---- 前端资源：从本次构建的 OUT_DIR 取（里面是 brotli 流） ----
    repo = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    assets = scan_codegen_assets(repo, blob)
    if assets:
        print("\n[i] 前端资源（本次构建 OUT_DIR，已 brotli 解包）")
        for name, data in sorted(assets.items()):
            # 按内容猜一个可读的文件名，方便与 dist/ 对照
            ext = ""
            head = data[:64]
            if head.lstrip().startswith(b"<") or b"<!DOCTYPE" in head or b"<html" in head:
                ext = ".html"
            elif b"function" in data[:2000] or b"=>" in data[:2000] or b"const " in data[:2000]:
                ext = ".js"
            elif b"{" in data[:400] and b":" in data[:200]:
                ext = ".css"
            open(os.path.join(outdir, name[:16] + ext), "wb").write(data)
            print(f"[+] {name[:16]+ext:<36} {len(data):>7} bytes  {sha(data)[:16]}")
    else:
        print("\n[i] 未找到构建 OUT_DIR，前端资源见仓库 dist/，详见本文件头注释")


if __name__ == "__main__":
    main()
