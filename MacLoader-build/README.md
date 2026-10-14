# MacLoader-build —— 唯一源码树

本目录是 MacLoader 的**唯一**源码树。所有改动都在这里做，不要在别处另建副本。

## 结构

| 路径 | 说明 |
|---|---|
| `dist/` | 前端静态页：`index.html` / `style.css` / `app.js` / `shell.js` / `logo.png` / `icons/`。构建时由 `tauri-codegen` 递归嵌入二进制 |
| `src-tauri/` | Rust 后端（`src/main.rs` 单文件）+ `tauri.conf.json` |
| `tools/verify.sh` | 与参考 `.app` 逐字节核对（⚠ 见下方「已知问题」） |
| `tools/extract.py` | 从 `.app` 二进制里抠出内嵌资源（`index.html` / `style.css` / `app.js` 都是 brotli 流） |
| `make_app.sh` | 手工拼 `.app`。Info.plist 与 `cargo tauri build` 产出的不一致，一般不用 |

## 构建

```bash
cd src-tauri
cargo tauri build
# → src-tauri/target/release/bundle/macos/MacLoader.app
```

窗口配置在 `src-tauri/tauri.conf.json`：默认 1080×720，下限 1024×700
（下限是按三列布局的最小不滚动尺寸定的，改布局要连带复核）。

## 改前端的注意事项

1. **改完同步 `../ui-preview/`**（预览靠 `mock.js` 顶掉 `window.__TAURI__`）
2. **用真实 WKWebView 量过再提交。** Blink 和 WebKit 的布局结果可能不同 ——
   CSS `columns` 多列就是踩过的坑：两个引擎均衡结果不一致，
   Chrome 里内容高 531px 放得下，WKWebView 里变 744px 直接出滚动条。
3. **`dist/` 里不要放临时文件**（`.bak`、草稿等）。`tauri-codegen` 会递归嵌入整个目录，
   产物体积和内容都会受影响。
4. `.DS_Store` 保留在版本库里是刻意的，见根目录 `.gitignore` 注释。

## 已知问题

`tools/verify.sh` 的默认参考路径是 `~/Downloads/MacLoader.app`，**该文件已不存在**。
而且本源码树的前端已相对参考产物做了布局修改，逐字节复现已不再是目标。
需要回归校验的话，建议改成校验「构建产物内嵌的 `index.html`/`style.css`/`app.js`
与 `dist/` 逐字节一致」—— 这才是当前真正会出错的环节。
