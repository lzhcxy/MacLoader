# WinLoader（MacLoader Windows 版）使用说明

`WinLoader.exe` 是 MacLoader 的 Windows 构建：同样的功能，跑在 Windows 上。
它是**免安装绿色版**，双击即用，不需要安装程序。

> 名字为什么不一样：原项目叫 MacLoader（macOS 上的 PE 构建器）。
> Windows 版沿用同一套代码，但产品名改叫 WinLoader，避免"Mac"字样误导。
> 二进制内部 identifier 仍是 `com.macloader.gui`，配置目录为
> `%APPDATA%\MacLoader`。

---

## 一、先装依赖（必做）

程序本体**只负责生成**，真正的编译/签名靠外部工具。Windows 上用 MSYS2 装：

### 1. 安装 MSYS2

到 <https://www.msys2.org> 下载安装，默认装到 `C:\msys64`。

### 2. 安装 mingw 工具链

打开 **MSYS2 UCRT64** 终端（开始菜单里找），执行：

```bash
pacman -S --needed mingw-w64-ucrt-x86_64-gcc
```

这条会带上 `g++`、`windres`、`strip`。

### 3. 安装 openssl 与 osslsigncode

```bash
pacman -S --needed openssl mingw-w64-ucrt-x86_64-osslsigncode
```

> 如果 MSYS2 源里没有 osslsigncode，从
> <https://github.com/mtrojnar/osslsigncode/releases> 取 Windows 构建，
> 把 `osslsigncode.exe` 放到 `C:\msys64\ucrt64\bin\` 即可。

### 4. 验证

启动 WinLoader，看左下角「环境自检」：

| 项 | 期望 |
|---|---|
| x64 | 显示 g++ 路径（不是"未找到"） |
| windres | 显示 windres 路径 |
| openssl | 显示 openssl 路径 |
| osslsigncode | 显示路径（不签名时可缺） |

**「未找到」的常见原因**：MSYS2 装在非默认路径。程序会额外搜
`C:\msys64\mingw64\bin`、`C:\msys64\ucrt64\bin`、`C:\tools\msys64\mingw64\bin`
等位置；如果你的 MSYS2 在别处，把它加进系统 PATH 再重启程序即可。

---

## 二、功能

与 macOS 版完全一致：

| 模块 | 说明 |
|---|---|
| C2 免杀 | payload → 编码/架构/执行方式/**免杀增强** → 带资源伪装与自签名的 exe |
| 变体矩阵 | 一次生成 16 个 exe，每个相对基线只改一处，便于归因 |
| Webshell 免杀 | PHP/ASP/ASPX/JSP，编码链 + 变量随机化 + 字符串拆分 |
| 产物自审 | 纯静态特征清单：熵值、RWX 节、资源、签名、时间戳、IAT、明文 API 名 |
| 配置方案 | 保存/载入/删除命名配置，自动记忆上次配置 |

命令行用法也一致（`WinLoader.exe --cli ...`），参数见 `--help`。

---

## 三、Windows 版与 macOS 版的差异

| 项 | macOS | Windows |
|---|---|---|
| 依赖安装 | 程序内一键 `brew install` | **不支持自动安装**，按上面手工装 MSYS2 |
| 配置目录 | `~/.macloader` | `%APPDATA%\MacLoader` |
| 编译器名 | `x86_64-w64-mingw32-g++` | 也认 MSYS2 的裸名 `g++` |
| 图片转 .ico | 自带 `sips` | 用 `magick`；没有时降级为单尺寸 ICO |
| 自动签名 | 需要 osslsigncode | 同 |

**依赖装不上时的提示**：程序会在「安装依赖」处直接给出 MSYS2 的 pacman
命令，照抄执行即可。

---

## 四、运行环境要求

- **Windows 10 1809 或更高**（x64）
- **WebView2 运行时**：Win11 已内置；Win10 若没装，程序首次启动会提示下载。
  离线环境可装 [Evergreen Standalone Installer](https://developer.microsoft.com/microsoft-edge/webview2/)。

---

## 五、产物说明

生成的 exe 是 Windows PE，功能与 macOS 版生成的一致。
自审页会列出静态引擎会抓的特征清单 —— 其中 `VirtualProtect` / `VirtualQuery`
由 mingw CRT 的启动代码引入，任何配置都恒定存在，属工具链固有成本。

固定随机序列请设环境变量 `MACLOADER_SEED=<n>`，同配置可产出逐字节相同的文件。
