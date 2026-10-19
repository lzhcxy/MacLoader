# MacLoader-build —— 唯一源码树

本目录是 MacLoader 的**唯一**源码树。所有改动都在这里做，不要在别处另建副本。

## 结构

| 路径 | 说明 |
|---|---|
| `dist/` | 前端静态页：`index.html` / `style.css` / `app.js` / `shell.js` / `logo.png` / `icons/`。构建时由 `tauri-codegen` 递归嵌入二进制 |
| `src-tauri/src/main.rs` | 只做三件事：补 PATH、CLI 解析、注册 Tauri 命令 |
| `src-tauri/src/builder/` | **构建逻辑本体**，按职责拆成子模块（见下） |
| `src-tauri/assets/loader.cpp` | 内嵌到产物里的 Windows 加载器（C++，由 mingw 交叉编译） |
| `tools/sync_preview.sh` | 把 `dist/` 同步到 `ui-preview/` 并补回 `mock.js` 引用（**别直接 rsync**） |
| `tools/verify.sh` | 构建产物一致性校验 |
| `tools/extract.py` | 从 `.app` 二进制 / 构建 OUT_DIR 还原内嵌资源（brotli 自动解包） |
| `make_app.sh` | 手工拼 `.app`。Info.plist 与 `cargo tauri build` 产出的不一致，一般不用 |

### `builder/` 子模块

| 模块 | 职责 |
|---|---|
| `tools.rs` | 外部工具探测（PATH + Homebrew 目录；GUI 从 Finder 启动时 PATH 很贫瘠） |
| `rng.rs` | 有状态 PRNG，支持 `MACLOADER_SEED` 复现 |
| `hash.rs` | 无依赖 SHA-256（证书缓存键、产物摘要） |
| `encode.rs` | payload 的 C 源码形态：UUID / Base64 / Base32 / 分块变密钥 / 垃圾翻译单元 |
| `resource.rs` | 图标库、ico 转换、VERSIONINFO / manifest / 诱饵资源；**保证图标-版本信息-证书主题三者自洽** |
| `pe.rs` | PE 解析、时间戳伪造、文件时间、熵值、RWX 节 |
| `sign.rs` | Authenticode 自签名（证书按 subject 缓存） |
| `payload.rs` | payload 文本 / 二进制解析 |
| `generate.rs` | 主生成流程 |
| `variants.rs` | 变体矩阵（一次 16 个，每个只改一处） |
| `webshell.rs` | Webshell 生成（PHP） |
| `inspect.rs` | 产物静态自审 |
| `profile.rs` | 配置方案持久化 |

## 构建

```bash
cd src-tauri
cargo tauri build
# → src-tauri/target/release/bundle/macos/MacLoader.app
./../tools/verify.sh          # 校验产物与 dist/ 是否一致
```

窗口配置在 `src-tauri/tauri.conf.json`：默认 1080×720，下限 1024×700
（下限是按三列布局的最小不滚动尺寸定的，改布局要连带复核）。

## 测试

```bash
cd src-tauri && cargo test --release
```

单元测试覆盖编码器往返、PE 解析、证书缓存、配置方案、Webshell 语法等。
**Webshell 有两条测试依赖本机 `php`**：`php -l` 语法检查与解码链端到端还原；
没装 php 时前者自动跳过。

## 改前端的注意事项

1. **改完同步 `../ui-preview/` 用脚本，不要直接 rsync**：

   ```bash
   ./tools/sync_preview.sh
   ```

   `dist/index.html` 里**不能**有 `mock.js`（真实构建会加载它，会顶掉真 runtime），
   而预览里**必须**有。直接 rsync 会把预览的引用冲掉，导致
   `window.__TAURI__` 未定义 → `app.js` 第一行就抛错 → 整个脚本挂掉，
   表现为「预览页所有模块空白、按钮全都没反应」，极易误判成布局 bug。
2. **用真实 WKWebView 量过再提交。** Blink 和 WebKit 的布局结果可能不同 ——
   CSS `columns` 多列就是踩过的坑：两个引擎均衡结果不一致，
   Chrome 里内容高 531px 放得下，WKWebView 里变 744px 直接出滚动条。
3. **`dist/` 里不要放临时文件**（`.bak`、草稿等）。`tauri-codegen` 会递归嵌入整个目录，
   产物体积和内容都会受影响。`tools/verify.sh` 会检查这一项。
4. `.DS_Store` 保留在版本库里是刻意的，见根目录 `.gitignore` 注释。

## 产物自审的定位

**特征清单，不是纯净度打分。**

凡是静态引擎会抓的特征，无论用户能否消除，一律如实列出并标注来源：

| 维度 | 看什么 | 能否消除 |
|---|---|---|
| 导入表特征（inject） | IAT 里的注入类 API | ✅ 能 —— 说明引入了额外静态依赖 |
| 导入表特征（mem） | IAT 里的内存类 API | ❌ 不能 —— mingw CRT 的 pseudo-reloc 必然带入，任何配置恒定存在 |
| 明文 API 名 | 字节层面的 API 名子串 | ⚠ 部分 —— loader 的 DJB2 哈希源串，需改成编译期常量 |

分数的意义仅在于「清单里 pass 项占多少」，不代表"越接近 100 越安全"。
改不掉的特征照样扣分会让人误以为配置有问题，所以这类项判 `warn` 并写明
"工具链固有成本"，由使用者自己权衡。

## 版本记录

### 1.3.0

修掉 5 个实测发现的缺陷：

| 级别 | 问题 | 修复 |
|---|---|---|
| P0 | 纯可打印的二进制 payload 被当成 hex 文本两两吞掉（8 字节 `ABCDEFGH` → 3 字节 `AB CD EF`），产物执行错误数据且不报错 | `payload.rs` 改为「扩展名 → 语法 → 文本外观」三级判定 |
| P0 | `MACLOADER_SEED` 承诺逐字节复现但做不到（唯一差异在 PE `CheckSum`，mingw 按输出布局算，不受种子控制） | `generate.rs` 在签名前调用 `pe::clear_checksum` 归零 |
| P1 | `cert_size` 读的是 SECURITY 目录的 VirtualAddress（文件偏移）而非 Size，自审显示「有证书表 (245760 bytes)」实为偏移 | `pe.rs` 改读 Size 字段 |
| P1 | GUI 完全没有 harden 入口，`hardenList()` 是返回 `[]` 的死桩，CLI 的五项加固 GUI 用不到 | 新增复选框组 + stomp-dll 输入 + stomp×protect 互斥联动 |
| P2 | 自审「可疑导入」全文搜子串，把 DJB2 哈希源串也算进去 → 100% 误报 | 拆成两维特征清单：IAT（按 inject/mem 分类标注来源）+ 明文 API 名（独立维度），命中项全部如实列出 |

单元测试 118 → 129，新增的回归用例覆盖：纯可打印二进制保真（1..64 字节）、
种子复现、SECURITY Size 读取、IAT 检测正负例。

## 已知问题

### 构建报 `failed to read plugin permissions` 且路径指向旧目录

`target/` 里缓存了构建脚本的**绝对路径**。本目录改名过（`loader/` → `Macloader/`），
老缓存仍指向旧路径。清掉重来即可：

```bash
rm -rf src-tauri/target/release/build/tauri-* \
       src-tauri/target/release/build/tauri-plugin-* \
       src-tauri/target/release/build/tauri-runtime-*
cd src-tauri && cargo tauri build
```

### `tools/verify.sh` 的 codesign 警告

`cargo tauri build` 产出的是 ad-hoc 签名，分发前需正式签名。预览用可以先：

```bash
codesign --force --deep --sign - MacLoader.app
```
