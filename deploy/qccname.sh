#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════
# qccname 节点启动脚本（Ubuntu 24.04 / 26.04）
#
#   目录结构（脚本所在目录即应用目录）：
#     qccname.sh  qccname.jar  qccname.properties  qcc-name-public-v1.0.0.json
#   数据与日志：~/qccname/{nodeId}/   ~/qccname/logs/
#
#   用法：./qccname.sh <命令>
#     start    环境检查 → 防火墙放行 → 后台启动，显示本次启动日志
#     stop     停止（先正常退出，10 秒后强制）
#     restart  stop + start
#     status   进程 / 内存 / 节点状态 / 最近一条 [进度]
#     log      实时跟踪当天运行日志（Ctrl+C 退出，不影响节点）
#     console  查看控制台输出最后 100 行（启动失败、异常堆栈看这里）
#     check    只做环境检查，不启动
#   内存：默认按本机内存自动选择，可用环境变量覆盖：QCCNAME_XMX=256m ./qccname.sh start
# ═══════════════════════════════════════════════════════════════════════════
set -euo pipefail

APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
JAR="$APP_DIR/qccname.jar"
CONF="$APP_DIR/qccname.properties"
SHARED_ROOT="$HOME/qccname"          # 同机实例共用：ssl/ web/ dev/
JAVA="${JAVA_HOME:+$JAVA_HOME/bin/}java"

red()   { printf '\033[31m%s\033[0m\n' "$*"; }
green() { printf '\033[32m%s\033[0m\n' "$*"; }
yellow(){ printf '\033[33m%s\033[0m\n' "$*"; }

SUDO=""
[ "$(id -u)" -ne 0 ] && command -v sudo >/dev/null 2>&1 && SUDO="sudo"

# ── 配置项读取 ─────────────────────────────────────────────────────────────
prop() { # prop key default
    local v
    v=$(grep -E "^[[:space:]]*$1[[:space:]]*=" "$CONF" 2>/dev/null | tail -1 | cut -d= -f2- | tr -d '[:space:]' || true)
    echo "${v:-$2}"
}

# ── 检查 ───────────────────────────────────────────────────────────────────
check_os() {
    if [ -r /etc/os-release ]; then
        . /etc/os-release
        case "${VERSION_ID:-}" in
            24.04|26.04) green "系统 $PRETTY_NAME" ;;
            *) yellow "系统 ${PRETTY_NAME:-未知}：脚本按 Ubuntu 24.04 / 26.04 编写，其他版本请自行核对" ;;
        esac
    fi
}

# ── Java：需要 23+；没有或版本过低时自动安装 Java 25 ─────────────────────
java_ver() { "$1" -version 2>&1 | grep -m1 'version "' | sed -E 's/.*version "([0-9]+).*/\1/'; }

# 依次找：JAVA_HOME → /usr/lib/jvm 下版本最高且 ≥23 的 → PATH 中的 java
find_java() {
    local best="" bestv=0 j v
    for j in ${JAVA_HOME:+$JAVA_HOME/bin/java} /usr/lib/jvm/*/bin/java "$(command -v java 2>/dev/null || true)"; do
        [ -n "$j" ] && [ -x "$j" ] || continue
        v=$(java_ver "$j"); v=${v:-0}
        if [ "$v" -gt "$bestv" ] 2>/dev/null; then best="$j"; bestv="$v"; fi
    done
    [ "$bestv" -ge 23 ] 2>/dev/null && { echo "$best"; return 0; }
    return 1
}

install_java25() {
    yellow "未找到 Java 23+，开始安装 Java 25 …"
    $SUDO apt-get update -qq
    # 1) Ubuntu 官方源（26.04 自带 openjdk-25）
    if apt-cache show openjdk-25-jre-headless >/dev/null 2>&1; then
        $SUDO DEBIAN_FRONTEND=noninteractive apt-get install -y -qq openjdk-25-jre-headless && return 0
    fi
    # 2) 官方源没有（如 24.04）：Amazon Corretto 25 官方 apt 源
    yellow "Ubuntu 源中没有 openjdk-25，改用 Amazon Corretto 25"
    $SUDO DEBIAN_FRONTEND=noninteractive apt-get install -y -qq wget gnupg ca-certificates
    wget -qO- https://apt.corretto.aws/corretto.key | $SUDO gpg --dearmor --yes -o /usr/share/keyrings/corretto-keyring.gpg
    echo "deb [signed-by=/usr/share/keyrings/corretto-keyring.gpg] https://apt.corretto.aws stable main" \
        | $SUDO tee /etc/apt/sources.list.d/corretto.list >/dev/null
    $SUDO apt-get update -qq
    $SUDO DEBIAN_FRONTEND=noninteractive apt-get install -y -qq java-25-amazon-corretto-jdk
}

check_java() {
    local j
    if ! j=$(find_java); then
        install_java25 || { red "Java 25 安装失败，请手工安装后重试"; exit 1; }
        j=$(find_java) || { red "安装完成但仍未找到 Java 23+"; exit 1; }
        green "Java 25 安装完成"
    fi
    JAVA="$j"
    # 只为本脚本选用该 java，不修改系统默认（避免影响本机其他 Java 程序）
    green "Java $(java_ver "$JAVA")  $JAVA"
}

# 每个实例一个应用目录、一个进程：数据 / 日志 / pid 都在 ~/qccname/{instance}（或配置的 home）
INSTANCE="$(prop instance qccname-test)"
DATA_ROOT="$(prop home "$SHARED_ROOT/$INSTANCE")"
LOG_DIR="$DATA_ROOT/logs"
PID_FILE="$DATA_ROOT/qccname.pid"
CONSOLE_LOG="$LOG_DIR/console.out"

check_files() {
    [ -f "$JAR" ]  || { red "缺少 $JAR（开发机 ./gradlew jar 生成 build/libs/qccname.jar）"; exit 1; }
    [ -f "$CONF" ] || { red "缺少 $CONF（参考 qccname.properties.example）"; exit 1; }
    local proto
    proto=$(prop protocol qcc-name-public-v1.0.0.json)
    case "$proto" in /*) ;; *) proto="$APP_DIR/$proto" ;; esac
    [ -f "$proto" ] || { red "缺少协议文件 $proto"; exit 1; }
    local key; key=$(prop clusterKey "")
    [ ${#key} -eq 64 ] || { red "qccname.properties 中 clusterKey 未配置或不是 64 位 hex"; exit 1; }
    [ -n "$(prop nodeId "")" ] || yellow "配置未写 nodeId，将使用代码默认 DEFAULT_NODE_ID"
}

check_time() {
    if command -v timedatectl >/dev/null 2>&1; then
        if [ "$(timedatectl show -p NTPSynchronized --value 2>/dev/null)" = "yes" ]; then
            green "时间已同步（NTP）"
        else
            yellow "时间未同步：节点间加密消息时间窗 ±60s，正在开启 NTP"
            $SUDO timedatectl set-ntp true || yellow "开启失败，请手工执行 sudo timedatectl set-ntp true"
        fi
    fi
}

check_ipv6() {
    if [ "$(cat /proc/sys/net/ipv6/conf/all/disable_ipv6 2>/dev/null || echo 1)" = "1" ]; then
        yellow "系统已禁用 IPv6：节点只监听 IPv4（IPv6 链节点 / 备份节点不可达）"
    else
        local g6; g6=$(ip -6 addr show scope global 2>/dev/null | awk '/inet6/{print $2}' | head -1)
        green "IPv6 已启用${g6:+，全局地址 $g6}"
    fi
}

# ── 防火墙：只放行，不擅自启用（启用 ufw 可能锁死 SSH）──────────────────
open_firewall() {
    open_port "$(prop port 9180)"
    local hp ks; hp=$(prop httpsPort 443); ks=$(prop keystore "$SHARED_ROOT/ssl/qccname.jks")
    if [ "$hp" != "0" ] && [ -f "$ks" ]; then open_port "$hp"; else echo "HTTPS 未启用（未找到证书 $ks）"; fi
    [ -d "$(prop webDir "$SHARED_ROOT/web")" ] && green "静态网站目录 $(prop webDir "$SHARED_ROOT/web")"
    yellow "提示：云厂商控制台的安全组 / 防火墙规则需另行放行以上端口（IPv4 与 IPv6）"
}

open_port() {
    local port="$1"
    if command -v ufw >/dev/null 2>&1 && $SUDO ufw status 2>/dev/null | grep -q "Status: active"; then
        if $SUDO ufw status | grep -qE "^${port}/tcp[[:space:]]+ALLOW"; then
            green "防火墙 ufw 已放行 ${port}/tcp"
        else
            $SUDO ufw allow "${port}/tcp" comment 'qccname' >/dev/null && green "防火墙 ufw 已放行 ${port}/tcp（IPv4 + IPv6）"
        fi
    elif command -v firewall-cmd >/dev/null 2>&1 && $SUDO firewall-cmd --state >/dev/null 2>&1; then
        if ! $SUDO firewall-cmd --query-port="${port}/tcp" >/dev/null 2>&1; then
            $SUDO firewall-cmd --permanent --add-port="${port}/tcp" >/dev/null 2>&1 && $SUDO firewall-cmd --reload >/dev/null
        fi
        green "防火墙 firewalld 已放行 ${port}/tcp"
    elif command -v iptables >/dev/null 2>&1 && $SUDO iptables -S INPUT 2>/dev/null | grep -q -- "-P INPUT DROP"; then
        $SUDO iptables  -C INPUT -p tcp --dport "$port" -j ACCEPT 2>/dev/null || $SUDO iptables  -I INPUT -p tcp --dport "$port" -j ACCEPT
        $SUDO ip6tables -C INPUT -p tcp --dport "$port" -j ACCEPT 2>/dev/null || $SUDO ip6tables -I INPUT -p tcp --dport "$port" -j ACCEPT 2>/dev/null || true
        yellow "iptables 已临时放行 ${port}/tcp（重启后失效，需持久化请装 iptables-persistent）"
    else
        green "本机防火墙未启用，${port}/tcp 无需放行"
    fi
}

# ── 内存：按本机内存自动选择 ───────────────────────────────────────────────
pick_xmx() {
    [ -n "${QCCNAME_XMX:-}" ] && { echo "$QCCNAME_XMX"; return; }
    local mem; mem=$(awk '/MemTotal/{print int($2/1024)}' /proc/meminfo)
    if   [ "$mem" -le 600 ];  then echo 128m    # 256M / 512M VPS
    elif [ "$mem" -le 1200 ]; then echo 256m    # 1G
    elif [ "$mem" -le 2500 ]; then echo 512m    # 2G
    else echo 768m; fi
}

running_pid() {
    [ -f "$PID_FILE" ] || return 1
    local pid; pid=$(cat "$PID_FILE")
    kill -0 "$pid" 2>/dev/null && grep -q "qccname.jar" "/proc/$pid/cmdline" 2>/dev/null && { echo "$pid"; return 0; }
    rm -f "$PID_FILE"; return 1
}

today_log() { echo "$LOG_DIR/qccname-$(date +%Y%m%d).log"; }

# ── 命令 ───────────────────────────────────────────────────────────────────
start() {
    if pid=$(running_pid); then yellow "已在运行 pid=$pid"; exit 0; fi
    check_os; check_java; check_files; check_time; check_ipv6; open_firewall
    mkdir -p "$LOG_DIR"
    local xmx; xmx=$(pick_xmx)
    JVM_OPTS=(
        -Xms64m "-Xmx$xmx" -Xss512k
        -XX:+UseSerialGC                       # 单核小内存最省；节点负载以签名验证为主，无需并行 GC
        -XX:MaxMetaspaceSize=96m -XX:ReservedCodeCacheSize=48m
        -XX:+ExitOnOutOfMemoryError            # OOM 直接退出，避免半死状态
        -Dstdout.encoding=UTF-8 -Dstderr.encoding=UTF-8 -Dfile.encoding=UTF-8
    )
    green "启动 qccname（-Xmx$xmx）…"
    cd "$APP_DIR"
    local offset=0
    [ -f "$CONSOLE_LOG" ] && offset=$(stat -c %s "$CONSOLE_LOG")
    echo "════════ $(date '+%F %T') start（-Xmx$xmx）════════" >> "$CONSOLE_LOG"
    # 用 -cp + 主类启动：普通 jar（无 Main-Class）与 fatJar 都能运行；lib/ 下的 jar（如 bcprov）一并加入
    nohup "$JAVA" "${JVM_OPTS[@]}" -cp "$JAR:$APP_DIR/lib/*" qcc.name.node.NodeMain >> "$CONSOLE_LOG" 2>&1 &
    echo $! > "$PID_FILE"
    # 等待启动完成（出现"集群"行）或进程退出，最多 20 秒；只显示本次启动的输出
    for _ in $(seq 1 40); do
        sleep 0.5
        running_pid >/dev/null || break
        tail -c +$((offset + 1)) "$CONSOLE_LOG" | grep -q "  集群 " && break
    done
    echo "──────── 本次启动日志 ────────"
    tail -c +$((offset + 1)) "$CONSOLE_LOG" | grep -v "^Picked up JAVA_TOOL_OPTIONS"
    echo "──────────────────────────────"
    if pid=$(running_pid); then
        green "已启动 pid=$pid"
        echo "  实时日志  ./qccname.sh log      状态  ./qccname.sh status      停止  ./qccname.sh stop"
        echo "  运行日志  $(today_log)"
        echo "  控制台    $CONSOLE_LOG"
    else
        red "启动失败（见上方输出；完整内容 ./qccname.sh console）"
        exit 1
    fi
}

stop() {
    if ! pid=$(running_pid); then yellow "未运行"; return 0; fi
    kill "$pid"
    for _ in $(seq 1 20); do kill -0 "$pid" 2>/dev/null || break; sleep 0.5; done
    if kill -0 "$pid" 2>/dev/null; then yellow "10 秒未退出，强制结束"; kill -9 "$pid"; fi
    rm -f "$PID_FILE"
    green "已停止"
}

status() {
    if pid=$(running_pid); then
        local rss; rss=$(awk '/VmRSS/{print int($2/1024)}' "/proc/$pid/status")
        green "运行中 pid=$pid  内存 RSS=${rss}MB"
        local port; port=$(prop port 9180)
        curl -s --max-time 3 "http://127.0.0.1:$port/v1/status" | sed -E 's/"cluster":\{.*\},"signer"/"cluster":{…},"signer"/' || yellow "HTTP 接口无响应"
        echo
        grep -hE "\[进度\] (主|备|冗余|尚未)" "$(today_log)" 2>/dev/null | tail -1
    else
        yellow "未运行"
    fi
}

case "${1:-}" in
    start)   start ;;
    stop)    stop ;;
    restart) stop; start ;;
    status)  status ;;
    log)     echo "跟踪 $(today_log)（Ctrl+C 退出，不影响节点）"; tail -n 50 -F "$(today_log)" ;;
    console) tail -n 100 "$CONSOLE_LOG" ;;
    check)   check_os; check_java; check_files; check_time; check_ipv6; open_firewall; echo "内存建议 -Xmx$(pick_xmx)" ;;
    *)
        echo "用法: $0 <命令>"
        echo "  start    启动（检查环境、放行防火墙、显示本次启动日志）"
        echo "  stop     停止"
        echo "  restart  重启"
        echo "  status   进程 / 内存 / 节点状态 / 最近进度"
        echo "  log      实时跟踪运行日志（[写入] / [同步] / [进度]）"
        echo "  console  控制台输出最后 100 行（启动失败看这里）"
        echo "  check    只检查环境，不启动"
        exit 1 ;;
esac
