# MacLoader

macOS 上的 Windows PE 构建器（含 Webshell 生成）。后端 Tauri 2 + Rust，
前端跑在 WKWebView 里，界面资源由 `tauri-codegen` 递归嵌入二进制。

## 功能模块

| 模块 | 说明 |
|---|---|
| **C2 免杀** | 选 payload → 编码 / 架构 / 执行方式 / 免杀增强 → 交叉编译出带资源伪装与自签名的 Windows exe |
| **变体矩阵** | 一次生成 16 个 exe，每个相对基线只改一处，实测后可直接归因到具体变量 |
| **Webshell 免杀** | PHP 生成：编码链（XOR/Base64/逆序/分块）+ 变量随机化 + 字符串拆分 |
| **产物自审** | 对生成的 exe 做纯静态检查：熵值、RWX 节、资源、签名、时间戳、可疑字符串，给出 0-100 分 |
| **配置方案** | 保存 / 载入 / 删除命名配置，并自动记忆上次配置 |

## 目录结构

| 路径 | 说明 |
|---|---|
| **`MacLoader-build/`** | **唯一源码树 —— 所有改动都在这里做** |
| `ui-preview/` | 纯浏览器预览（`mock.js` 顶掉 `window.__TAURI__`），不参与构建 |
| `_ui-review/` | 布局变更的改前改后截图 |
| `_backup/` | 原始应用备份。**已 gitignore，但不要删** —— 见下 |

## 唯一事实源

前端和后端都只在 `MacLoader-build/` 改；前端改完同步到 `ui-preview/`。
**不要再建第二套前端副本。**

旧的 `maloader-src/`（旧版 UI 的反编译还原树）已删除。需要时从历史恢复：

```bash
git checkout 56dd699 -- maloader-src
```

## 构建

```bash
cd MacLoader-build/src-tauri
cargo tauri build
# → src-tauri/target/release/bundle/macos/MacLoader.app
cd .. && ./tools/verify.sh    # 校验产物与 dist/ 一致性
cargo test --release          # 单元测试
```

## 命令行

GUI 之外也提供无界面模式，便于批量与自动化：

```bash
# PE 构建
macloader --cli --payload p.bin --out-dir out --encoding chunk --icon lib:pdf

# 变体矩阵（16 个只差一个变量的 exe）
macloader --cli --payload p.bin --out-dir out --matrix

# Webshell
macloader --cli --ws --ws-password pass --out-dir out --name shell.php

# 静态自审
macloader --cli --inspect out/loader.exe
```

同一配置想产出逐字节相同的文件，用 `MACLOADER_SEED=<n>` 固定随机序列。
（v1.3.0 起才真正成立：此前 mingw 写入的 PE `CheckSum` 不受种子控制，
同种子两次产物仍差一个字段；现在构建时已归零该字段。）

## ⚠ 改前端前必读

1. **用真实 WebKit 量过再提交。** Blink 和 WebKit 的布局结果可能不同 ——
   三列布局踩过这个坑：CSS `columns` 多列在两个引擎下均衡结果不一致，
   Chrome 里正好放下，WKWebView 里多出 143px 直接出现纵向滚动条。
   量之前先确认用的是 WKWebView，不是 Chrome 的推算。
2. **`dist/` 里不要放临时文件。** `tauri-codegen` 会递归嵌入整个目录，
   连 `.DS_Store` 都会进二进制（所以 `.gitignore` 故意不忽略它）。
3. 控件尺寸用整数像素，避免半像素在 Retina 上发虚。

## `_backup/` 说明

`_backup/MacLoader.app-20261014-111353/` 是**原始应用的唯一副本**：
`/Applications` 里那份已被当前版本替换，`~/Downloads/MacLoader.app` 也已不在。

已核验它与参考产物逐字节一致：

| 文件 | sha256 |
|---|---|
| `Contents/MacOS/macloader` | `d9e5ef2c…b588` |
| `Contents/Info.plist` | `7e789a1c…3581` |

改坏了要回退，直接把 `_backup/MacLoader.app-*` 拷回 `/Applications` 并重新 ad-hoc 签名即可。
