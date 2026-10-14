# maloader-src2 —— MacLoader.app 反编译还原源码

本目录是 `/Users/sys0ne/Downloads/MacLoader.app` 的**反编译还原**结果。
用 `cargo tauri build` 构建后，产物与参考 `.app` **逐字节相同**：

| 文件 | 参考 sha256 | 本仓库重建 |
|---|---|---|
| `Contents/MacOS/macloader` | `d9e5ef2c…b588` | ✅ 一致 |
| `Contents/Info.plist` | `7e789a1c…3581` | ✅ 一致 |
| `Contents/Resources/MacLoader.icns` | `c12d8646…217e` | ✅ 一致 |

还原方法与结论见 [`decompiled/反编译报告.md`](decompiled/反编译报告.md)。

## 构建

```bash
cd src-tauri
cargo tauri build
# → src-tauri/target/release/bundle/macos/MacLoader.app
```

> ⚠ 不要用 `make_app.sh` 去“复现参考产物”—— 它手工组装的 `.app`
> （Info.plist 可执行名/图标名/版本下限都不同）与参考产物不一致。
> 参考产物是 `cargo tauri build` 直接出的完整 bundle。

## 还原工具

```bash
python3 tools/extract.py <MacLoader.app> <输出目录>
```

从二进制里抠出 `loader.cpp`（明文）与图标（原样嵌入）等。

## 与 maloader-src 的关系

- `maloader-src/`：开发版，含后续改进（如证书缓存修复）。
- `maloader-src2/`：**参考产物对应的确切源码**，用于复现 / 对照。

两者 `main.rs` 及绝大部分资源相同；差异见反编译报告第五节。
