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


def main():
    if len(sys.argv) < 3:
        print(__doc__)
        sys.exit(1)
    app, outdir = sys.argv[1], sys.argv[2]
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

    print("\n[i] brotli 压缩的前端资源见仓库 dist/ 或构建 OUT_DIR，详见本文件头注释")


if __name__ == "__main__":
    main()
