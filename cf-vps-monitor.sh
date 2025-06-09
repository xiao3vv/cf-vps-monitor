#!/bin/bash

# cf-vps-monitor - Cloudflare Worker VPS监控脚本
# 版本: 3.0 - 匹配最新worker.js
# 支持所有常见Linux系统，无需root权限

set -euo pipefail

# 初始化系统类型变量
OS=$(uname -s)
export OS

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# 全局变量
SCRIPT_DIR="$HOME/.cf-vps-monitor"
CONFIG_FILE="$SCRIPT_DIR/config"
LOG_FILE="$SCRIPT_DIR/monitor.log"
PID_FILE="$SCRIPT_DIR/monitor.pid"
SERVICE_FILE="$SCRIPT_DIR/vps-monitor-service.sh"
SYSTEMD_SERVICE_FILE="$HOME/.config/systemd/user/cf-vps-monitor.service"

# 默认配置
DEFAULT_INTERVAL=60
DEFAULT_WORKER_URL=""
DEFAULT_SERVER_ID=""
DEFAULT_API_KEY=""

# 打印带颜色的消息
print_message() {
    local color=$1
    local message=$2
    echo -e "${color}${message}${NC}"
}

# 日志函数
log() {
    local message="$1"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[$timestamp] $message" >> "$LOG_FILE"
    echo "[$timestamp] $message"
}

# 错误处理
error_exit() {
    local message="$1"
    print_message "$RED" "错误: $message"
    log "ERROR: $message"
    exit 1
}

# 检查命令是否存在
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# 检测系统信息
detect_system() {
    OS=$(uname -s)

    if [[ "$OS" == "FreeBSD" ]]; then
        VER=$(uname -r)
        print_message "$CYAN" "检测到系统: FreeBSD $VER"
        return
    fi

    # 检测容器环境
    if [[ -f /.dockerenv ]] || [[ -n "${container:-}" ]]; then
        CONTAINER_ENV="true"
        print_message "$YELLOW" "检测到容器环境"
    else
        CONTAINER_ENV="false"
    fi

    # 多种方式检测Linux发行版
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        OS=$NAME
        VER=$VERSION_ID
        DISTRO_ID=$ID
    elif [[ -f /etc/lsb-release ]]; then
        . /etc/lsb-release
        OS=$DISTRIB_ID
        VER=$DISTRIB_RELEASE
        DISTRO_ID=$(echo "$OS" | tr '[:upper:]' '[:lower:]')
    elif command_exists lsb_release; then
        OS=$(lsb_release -si)
        VER=$(lsb_release -sr)
        DISTRO_ID=$(echo "$OS" | tr '[:upper:]' '[:lower:]')
    elif [[ -f /etc/redhat-release ]]; then
        OS=$(cat /etc/redhat-release | sed 's/ release.*//')
        VER=$(cat /etc/redhat-release | sed 's/.*release //' | sed 's/ .*//')
        DISTRO_ID="rhel"
    elif [[ -f /etc/centos-release ]]; then
        OS="CentOS"
        VER=$(cat /etc/centos-release | sed 's/.*release //' | sed 's/ .*//')
        DISTRO_ID="centos"
    elif [[ -f /etc/debian_version ]]; then
        OS="Debian"
        VER=$(cat /etc/debian_version)
        DISTRO_ID="debian"
    elif [[ -f /etc/alpine-release ]]; then
        OS="Alpine Linux"
        VER=$(cat /etc/alpine-release)
        DISTRO_ID="alpine"
    elif [[ -f /etc/arch-release ]]; then
        OS="Arch Linux"
        VER="rolling"
        DISTRO_ID="arch"
    else
        OS="Linux"
        VER=$(uname -r)
        DISTRO_ID="unknown"
    fi

    print_message "$CYAN" "检测到系统: $OS $VER"
    if [[ "$CONTAINER_ENV" == "true" ]]; then
        print_message "$YELLOW" "运行在容器环境中"
    fi

    # 确保变量在全局可用
    export OS VER DISTRO_ID CONTAINER_ENV
}

# 检测包管理器
detect_package_manager() {
    PKG_MANAGER=""
    PKG_INSTALL=""
    PKG_UPDATE=""

    if [[ "$OS" == "FreeBSD" ]]; then
        if command_exists pkg; then
            PKG_MANAGER="pkg"
            PKG_INSTALL="pkg install -y"
            PKG_UPDATE="pkg update"
        fi
    else
        # 按优先级检测包管理器
        if command_exists apt-get; then
            PKG_MANAGER="apt-get"
            PKG_INSTALL="apt-get install -y"
            PKG_UPDATE="apt-get update"
        elif command_exists apt; then
            PKG_MANAGER="apt"
            PKG_INSTALL="apt install -y"
            PKG_UPDATE="apt update"
        elif command_exists dnf; then
            PKG_MANAGER="dnf"
            PKG_INSTALL="dnf install -y"
            PKG_UPDATE="dnf update -y"
        elif command_exists yum; then
            PKG_MANAGER="yum"
            PKG_INSTALL="yum install -y"
            PKG_UPDATE="yum update -y"
        elif command_exists zypper; then
            PKG_MANAGER="zypper"
            PKG_INSTALL="zypper install -y"
            PKG_UPDATE="zypper refresh"
        elif command_exists pacman; then
            PKG_MANAGER="pacman"
            PKG_INSTALL="pacman -S --noconfirm"
            PKG_UPDATE="pacman -Sy"
        elif command_exists apk; then
            PKG_MANAGER="apk"
            PKG_INSTALL="apk add"
            PKG_UPDATE="apk update"
        elif command_exists emerge; then
            PKG_MANAGER="emerge"
            PKG_INSTALL="emerge"
            PKG_UPDATE="emerge --sync"
        elif command_exists xbps-install; then
            PKG_MANAGER="xbps"
            PKG_INSTALL="xbps-install -y"
            PKG_UPDATE="xbps-install -S"
        elif command_exists swupd; then
            PKG_MANAGER="swupd"
            PKG_INSTALL="swupd bundle-add"
            PKG_UPDATE="swupd update"
        elif command_exists nix-env; then
            PKG_MANAGER="nix"
            PKG_INSTALL="nix-env -i"
            PKG_UPDATE="nix-channel --update"
        fi
    fi

    if [[ -n "$PKG_MANAGER" ]]; then
        print_message "$GREEN" "检测到包管理器: $PKG_MANAGER"
    else
        print_message "$YELLOW" "警告: 未检测到支持的包管理器，将尝试手动安装依赖"
    fi

    # 导出变量供其他函数使用
    export PKG_MANAGER PKG_INSTALL PKG_UPDATE
}

# 检查并安装依赖（无需root权限的方法）
install_dependencies() {
    print_message "$BLUE" "检查系统依赖..."
    
    local missing_deps=()
    
    # 检查必需的命令
    if ! command_exists curl; then
        missing_deps+=("curl")
    fi
    
    if ! command_exists bc; then
        missing_deps+=("bc")
    fi
    
    # 检查可选的命令
    local optional_missing=()
    if ! command_exists ifstat; then
        optional_missing+=("ifstat")
    fi
    if ! command_exists jq; then
        optional_missing+=("jq")
    fi

    # 报告可选依赖状态
    if [[ ${#optional_missing[@]} -gt 0 ]]; then
        print_message "$YELLOW" "可选依赖未安装: ${optional_missing[*]}"
        print_message "$YELLOW" "这些依赖缺失不会影响基本功能，但可能限制某些特性"
    fi

    if [[ ${#missing_deps[@]} -eq 0 ]]; then
        print_message "$GREEN" "所有必需依赖已安装"
        return 0
    fi

    print_message "$YELLOW" "缺少必需依赖: ${missing_deps[*]}"

    # 根据不同发行版调整包名
    local adjusted_deps=()
    for dep in "${missing_deps[@]}"; do
        case "$dep" in
            "bc")
                if [[ "$DISTRO_ID" == "alpine" ]]; then
                    adjusted_deps+=("bc")
                else
                    adjusted_deps+=("bc")
                fi
                ;;
            "curl")
                adjusted_deps+=("curl")
                ;;
            *)
                adjusted_deps+=("$dep")
                ;;
        esac
    done

    # 尝试安装依赖
    if [[ -n "$PKG_MANAGER" ]]; then
        if command_exists sudo && sudo -n true 2>/dev/null; then
            print_message "$BLUE" "尝试使用sudo安装依赖..."
            # 先更新包列表（对于某些包管理器）
            if [[ "$PKG_MANAGER" == "apt-get" ]] || [[ "$PKG_MANAGER" == "apt" ]]; then
                sudo $PKG_UPDATE
            fi

            for dep in "${adjusted_deps[@]}"; do
                print_message "$BLUE" "安装 $dep..."
                if ! sudo $PKG_INSTALL "$dep"; then
                    print_message "$YELLOW" "警告: 无法安装 $dep"
                fi
            done
        else
            print_message "$YELLOW" "需要sudo权限安装依赖，请手动执行:"
            print_message "$CYAN" "  sudo $PKG_INSTALL ${adjusted_deps[*]}"
        fi
    else
        print_message "$YELLOW" "未检测到包管理器，请手动安装依赖"
        print_message "$CYAN" "常见安装命令:"
        print_message "$CYAN" "  Ubuntu/Debian: sudo apt-get install ${adjusted_deps[*]}"
        print_message "$CYAN" "  CentOS/RHEL: sudo yum install ${adjusted_deps[*]}"
        print_message "$CYAN" "  Fedora: sudo dnf install ${adjusted_deps[*]}"
        print_message "$CYAN" "  Alpine: sudo apk add ${adjusted_deps[*]}"
    fi

    # 再次检查关键依赖
    if ! command_exists curl; then
        print_message "$RED" "curl是必需的依赖，正在尝试替代方案..."

        # 尝试使用wget作为curl的替代
        if command_exists wget; then
            print_message "$YELLOW" "将使用wget作为curl的替代"
            # 创建curl的wrapper函数
            create_curl_wrapper
        else
            error_exit "curl和wget都不可用，请先安装其中一个后重试"
        fi
    fi

    if ! command_exists bc; then
        print_message "$YELLOW" "警告: bc未安装，将使用内置的数学计算"
        # 创建bc的替代函数
        create_bc_wrapper
    fi
    
    print_message "$GREEN" "依赖检查完成"
}

# 创建curl的wrapper函数（使用wget）
create_curl_wrapper() {
    cat > "$SCRIPT_DIR/curl_wrapper.sh" << 'EOF'
#!/bin/bash
# curl wrapper using wget

# 解析curl参数
method="GET"
url=""
headers=()
data=""
output_headers=false
silent=false

while [[ $# -gt 0 ]]; do
    case $1 in
        -X)
            method="$2"
            shift 2
            ;;
        -H)
            headers+=("$2")
            shift 2
            ;;
        -d)
            data="$2"
            method="POST"
            shift 2
            ;;
        -s)
            silent=true
            shift
            ;;
        -w)
            if [[ "$2" == "%{http_code}" ]]; then
                output_headers=true
            fi
            shift 2
            ;;
        *)
            url="$1"
            shift
            ;;
    esac
done

# 构建wget命令
wget_cmd="wget -q -O-"

# 添加headers
for header in "${headers[@]}"; do
    wget_cmd="$wget_cmd --header='$header'"
done

# 添加POST数据
if [[ -n "$data" ]]; then
    wget_cmd="$wget_cmd --post-data='$data'"
fi

# 执行请求
if [[ "$output_headers" == "true" ]]; then
    # 需要返回HTTP状态码
    temp_file=$(mktemp)
    eval "$wget_cmd --server-response '$url'" > "$temp_file" 2>&1

    # 提取状态码
    status_code=$(grep "HTTP/" "$temp_file" | tail -1 | awk '{print $2}' || echo "200")

    # 输出内容和状态码
    grep -v "HTTP/" "$temp_file" 2>/dev/null || echo ""
    echo -n "$status_code"

    rm -f "$temp_file"
else
    eval "$wget_cmd '$url'"
fi
EOF

    chmod +x "$SCRIPT_DIR/curl_wrapper.sh"

    # 创建curl别名
    alias curl="$SCRIPT_DIR/curl_wrapper.sh"
    export -f curl 2>/dev/null || true
}

# 创建bc的wrapper函数（使用awk）
create_bc_wrapper() {
    cat > "$SCRIPT_DIR/bc_wrapper.sh" << 'EOF'
#!/bin/bash
# bc wrapper using awk

# 读取输入
if [[ $# -gt 0 ]]; then
    expression="$1"
else
    read -r expression
fi

# 使用awk进行计算
echo "$expression" | awk '
{
    # 替换scale=N为空
    gsub(/scale=[0-9]+;/, "")

    # 计算表达式
    result = eval_expr($0)

    # 格式化输出
    if (result == int(result)) {
        printf "%.0f\n", result
    } else {
        printf "%.1f\n", result
    }
}

function eval_expr(expr) {
    # 简单的数学表达式计算
    # 支持基本的四则运算
    return eval(expr)
}

function eval(expr) {
    # 使用awk的内置计算能力
    cmd = "echo \"" expr "\" | awk \"BEGIN{print " expr "}\""
    cmd | getline result
    close(cmd)
    return result
}
'
EOF

    chmod +x "$SCRIPT_DIR/bc_wrapper.sh"

    # 创建bc别名
    alias bc="$SCRIPT_DIR/bc_wrapper.sh"
    export -f bc 2>/dev/null || true
}

# 创建目录结构
create_directories() {
    print_message "$BLUE" "创建目录结构..."

    # 检查当前用户权限
    local current_user=$(whoami)
    local user_home="$HOME"

    # 如果没有指定SCRIPT_DIR或无法写入默认位置，使用用户目录
    if [[ "$SCRIPT_DIR" == "/opt/vps-monitor" && ! -w "/opt" ]] 2>/dev/null; then
        SCRIPT_DIR="$user_home/.local/share/vps-monitor"
        print_message "$YELLOW" "没有/opt写权限，使用用户目录: $SCRIPT_DIR"
    fi

    # 创建主目录
    if ! mkdir -p "$SCRIPT_DIR" 2>/dev/null; then
        # 如果创建失败，尝试使用用户目录
        SCRIPT_DIR="$user_home/.local/share/vps-monitor"
        print_message "$YELLOW" "使用备用目录: $SCRIPT_DIR"
        mkdir -p "$SCRIPT_DIR" || error_exit "无法创建目录: $SCRIPT_DIR"
    fi

    # 更新相关路径变量
    CONFIG_FILE="$SCRIPT_DIR/config"
    SERVICE_FILE="$SCRIPT_DIR/vps-monitor-service.sh"
    PID_FILE="$SCRIPT_DIR/vps-monitor.pid"

    # 处理日志目录
    if [[ "$LOG_FILE" == "/var/log/vps-monitor/vps-monitor.log" && ! -w "/var/log" ]] 2>/dev/null; then
        LOG_FILE="$SCRIPT_DIR/vps-monitor.log"
        print_message "$YELLOW" "没有/var/log写权限，使用: $LOG_FILE"
    fi

    # 创建systemd用户目录
    local systemd_user_dir="$user_home/.config/systemd/user"
    if command_exists systemctl; then
        if ! mkdir -p "$systemd_user_dir" 2>/dev/null; then
            print_message "$YELLOW" "警告: 无法创建systemd用户目录，将使用传统服务方式"
        else
            SYSTEMD_SERVICE_FILE="$systemd_user_dir/cf-vps-monitor.service"
        fi
    fi

    # 创建日志文件
    if ! touch "$LOG_FILE" 2>/dev/null; then
        LOG_FILE="$SCRIPT_DIR/vps-monitor.log"
        touch "$LOG_FILE" || error_exit "无法创建日志文件: $LOG_FILE"
    fi

    print_message "$GREEN" "目录结构创建完成"
    print_message "$CYAN" "  主目录: $SCRIPT_DIR"
    print_message "$CYAN" "  日志文件: $LOG_FILE"

    # 导出更新后的变量
    export SCRIPT_DIR CONFIG_FILE SERVICE_FILE PID_FILE LOG_FILE SYSTEMD_SERVICE_FILE
}

# 加载配置
load_config() {
    if [[ -f "$CONFIG_FILE" ]]; then
        source "$CONFIG_FILE"
    else
        WORKER_URL="$DEFAULT_WORKER_URL"
        SERVER_ID="$DEFAULT_SERVER_ID"
        API_KEY="$DEFAULT_API_KEY"
        INTERVAL="$DEFAULT_INTERVAL"
    fi
}

# 保存配置
save_config() {
    cat > "$CONFIG_FILE" << EOF
# VPS监控配置文件
WORKER_URL="$WORKER_URL"
SERVER_ID="$SERVER_ID"
API_KEY="$API_KEY"
INTERVAL="$INTERVAL"
EOF
    print_message "$GREEN" "配置已保存到 $CONFIG_FILE"
}

# 获取CPU使用率
get_cpu_usage() {
    local cpu_usage
    local cpu_load

    # FreeBSD系统
    if [[ "$OS" == "FreeBSD" ]]; then
        # 使用sysctl获取CPU使用率
        if command_exists sysctl; then
            local cpu_idle=$(sysctl -n kern.cp_time 2>/dev/null | awk '{print $5}' 2>/dev/null || echo "0")
            local cpu_total=$(sysctl -n kern.cp_time 2>/dev/null | awk '{sum=0; for(i=1;i<=NF;i++) sum+=$i; print sum}' 2>/dev/null || echo "0")

            # 确保获取到有效数值
            cpu_idle=$(sanitize_integer "$cpu_idle" "0")
            cpu_total=$(sanitize_integer "$cpu_total" "0")

            if [[ $cpu_total -gt 0 && $cpu_idle -le $cpu_total ]]; then
                cpu_usage=$(echo "scale=1; 100 - ($cpu_idle * 100 / $cpu_total)" | bc 2>/dev/null || echo "0")
                # 确保cpu_usage是有效的数字
                cpu_usage=$(sanitize_number "$cpu_usage" "0")
            else
                cpu_usage="0"
            fi
        else
            cpu_usage="0"
        fi

        # FreeBSD负载平均值
        local load1="0" load5="0" load15="0"
        if command_exists sysctl; then
            load1=$(sysctl -n vm.loadavg 2>/dev/null | awk '{print $2}' 2>/dev/null || echo "0")
            load5=$(sysctl -n vm.loadavg 2>/dev/null | awk '{print $3}' 2>/dev/null || echo "0")
            load15=$(sysctl -n vm.loadavg 2>/dev/null | awk '{print $4}' 2>/dev/null || echo "0")

            # 清理负载数值
            load1=$(sanitize_number "$load1" "0")
            load5=$(sanitize_number "$load5" "0")
            load15=$(sanitize_number "$load15" "0")
        fi

        cpu_load="$load1,$load5,$load15"
    else
        # Linux系统 - 多种方法提高兼容性
        cpu_usage="0"

        # 方法1: 使用/proc/stat（最准确的方法）
        if [[ -f /proc/stat ]]; then
            local cpu_line=$(head -n1 /proc/stat 2>/dev/null)
            if [[ -n "$cpu_line" ]]; then
                local cpu_times=($cpu_line)
                if [[ ${#cpu_times[@]} -ge 8 ]]; then
                    local idle=${cpu_times[4]}
                    local iowait=${cpu_times[5]:-0}
                    local total=0

                    # 计算总CPU时间（user + nice + system + idle + iowait + irq + softirq + steal）
                    for i in {1..7}; do
                        if [[ -n "${cpu_times[i]}" && "${cpu_times[i]}" =~ ^[0-9]+$ ]]; then
                            total=$((total + cpu_times[i]))
                        fi
                    done

                    if [[ $total -gt 0 ]]; then
                        cpu_usage=$(echo "scale=1; 100 - (($idle + $iowait) * 100 / $total)" | bc 2>/dev/null || echo "0")
                    fi
                fi
            fi
        fi

        # 方法2: 使用top命令（如果/proc/stat不可用）
        if [[ "$cpu_usage" == "0" ]] && command_exists top; then
            # 尝试不同的top输出格式
            local top_output=$(timeout 3 top -bn1 2>/dev/null | head -10)
            if [[ -n "$top_output" ]]; then
                # 匹配不同格式的CPU行
                if [[ "$top_output" =~ %Cpu\(s\):[[:space:]]*([0-9.]+)[[:space:]]*us.*[[:space:]]+([0-9.]+)[[:space:]]*id ]]; then
                    # 格式: %Cpu(s): 12.5 us, 2.1 sy, 0.0 ni, 85.4 id
                    local idle_percent="${BASH_REMATCH[2]}"
                    cpu_usage=$(echo "scale=1; 100 - $idle_percent" | bc 2>/dev/null || echo "0")
                elif [[ "$top_output" =~ CPU:[[:space:]]*([0-9.]+)%[[:space:]]*us.*[[:space:]]+([0-9.]+)%[[:space:]]*id ]]; then
                    # 格式: CPU: 12.5% us, 2.1% sy, 85.4% id
                    local idle_percent="${BASH_REMATCH[2]}"
                    cpu_usage=$(echo "scale=1; 100 - $idle_percent" | bc 2>/dev/null || echo "0")
                fi
            fi
        fi

        # 方法3: 使用vmstat命令（备用方法）
        if [[ "$cpu_usage" == "0" ]] && command_exists vmstat; then
            local vmstat_output=$(timeout 3 vmstat 1 2 2>/dev/null | tail -1)
            if [[ -n "$vmstat_output" ]]; then
                local idle_percent=$(echo "$vmstat_output" | awk '{print $(NF-2)}' 2>/dev/null || echo "100")
                if [[ "$idle_percent" =~ ^[0-9]+$ ]]; then
                    cpu_usage=$((100 - idle_percent))
                fi
            fi
        fi

        # 确保cpu_usage是有效的数字
        cpu_usage=$(sanitize_number "$cpu_usage" "0")

        # 获取负载平均值 - 多种方法
        local load1="0" load5="0" load15="0"
        if [[ -f /proc/loadavg ]]; then
            local load_data=$(cat /proc/loadavg 2>/dev/null | awk '{print $1" "$2" "$3}' || echo "0 0 0")
            read -r load1 load5 load15 <<< "$load_data"
        elif command_exists uptime; then
            # 尝试从uptime命令获取负载
            local uptime_output=$(uptime 2>/dev/null)
            if [[ "$uptime_output" =~ load[[:space:]]+average:[[:space:]]*([0-9.]+),[[:space:]]*([0-9.]+),[[:space:]]*([0-9.]+) ]]; then
                load1="${BASH_REMATCH[1]}"
                load5="${BASH_REMATCH[2]}"
                load15="${BASH_REMATCH[3]}"
            elif [[ "$uptime_output" =~ ([0-9.]+)[[:space:]]+([0-9.]+)[[:space:]]+([0-9.]+)$ ]]; then
                load1="${BASH_REMATCH[1]}"
                load5="${BASH_REMATCH[2]}"
                load15="${BASH_REMATCH[3]}"
            fi
        fi

        # 清理和验证每个负载值
        load1=$(sanitize_number "$load1" "0")
        load5=$(sanitize_number "$load5" "0")
        load15=$(sanitize_number "$load15" "0")

        cpu_load="$load1,$load5,$load15"
    fi

    echo "{\"usage_percent\":$cpu_usage,\"load_avg\":[$cpu_load]}"
}

# 获取内存使用情况
get_memory_usage() {
    local total used free usage_percent

    # FreeBSD系统
    if [[ "$OS" == "FreeBSD" ]]; then
        if command_exists sysctl; then
            # FreeBSD内存信息
            local page_size=$(sysctl -n hw.pagesize 2>/dev/null || echo "4096")
            local total_pages=$(sysctl -n vm.stats.vm.v_page_count 2>/dev/null || echo "0")
            local free_pages=$(sysctl -n vm.stats.vm.v_free_count 2>/dev/null || echo "0")
            local inactive_pages=$(sysctl -n vm.stats.vm.v_inactive_count 2>/dev/null || echo "0")
            local cache_pages=$(sysctl -n vm.stats.vm.v_cache_count 2>/dev/null || echo "0")

            # 清理和验证数值
            page_size=$(sanitize_integer "$page_size" "4096")
            total_pages=$(sanitize_integer "$total_pages" "0")
            free_pages=$(sanitize_integer "$free_pages" "0")
            inactive_pages=$(sanitize_integer "$inactive_pages" "0")
            cache_pages=$(sanitize_integer "$cache_pages" "0")

            # 计算内存（转换为KB）
            if [[ $page_size -gt 0 && $total_pages -gt 0 ]]; then
                total=$(( (total_pages * page_size) / 1024 ))
                free=$(( ((free_pages + inactive_pages + cache_pages) * page_size) / 1024 ))
                used=$((total - free))

                # 确保数值合理
                if [[ $used -lt 0 ]]; then
                    used=0
                fi
                if [[ $free -lt 0 ]]; then
                    free=0
                fi
            else
                total=0
                used=0
                free=0
            fi
        else
            total=0
            used=0
            free=0
        fi
    else
        # Linux系统 - 多种方法提高兼容性
        if command_exists free; then
            # 方法1: 使用free命令（最常用）
            local mem_info=$(free -k 2>/dev/null | grep "^Mem:")
            if [[ -n "$mem_info" ]]; then
                total=$(echo "$mem_info" | awk '{print $2}')
                used=$(echo "$mem_info" | awk '{print $3}')
                free=$(echo "$mem_info" | awk '{print $4}')

                # 在某些系统上，free命令的输出格式可能不同
                # 如果第3列不是used，尝试计算
                if [[ ! "$used" =~ ^[0-9]+$ ]]; then
                    local available=$(echo "$mem_info" | awk '{print $7}' 2>/dev/null || echo "0")
                    if [[ "$available" =~ ^[0-9]+$ ]]; then
                        used=$((total - available))
                    else
                        used=$((total - free))
                    fi
                fi
            fi
        fi

        # 方法2: 直接读取/proc/meminfo（备用方法）
        if [[ -z "$total" || "$total" == "0" ]] && [[ -f /proc/meminfo ]]; then
            total=$(grep "^MemTotal:" /proc/meminfo | awk '{print $2}' 2>/dev/null || echo "0")
            local mem_free=$(grep "^MemFree:" /proc/meminfo | awk '{print $2}' 2>/dev/null || echo "0")
            local buffers=$(grep "^Buffers:" /proc/meminfo | awk '{print $2}' 2>/dev/null || echo "0")
            local cached=$(grep "^Cached:" /proc/meminfo | awk '{print $2}' 2>/dev/null || echo "0")

            # 计算实际可用内存
            free=$((mem_free + buffers + cached))
            used=$((total - free))
        fi

        # 方法3: 容器环境特殊处理
        if [[ "$CONTAINER_ENV" == "true" && -f /sys/fs/cgroup/memory/memory.limit_in_bytes ]]; then
            local cgroup_limit=$(cat /sys/fs/cgroup/memory/memory.limit_in_bytes 2>/dev/null || echo "0")
            local cgroup_usage=$(cat /sys/fs/cgroup/memory/memory.usage_in_bytes 2>/dev/null || echo "0")

            # 如果cgroup限制合理（不是一个巨大的数字），使用cgroup数据
            if [[ "$cgroup_limit" =~ ^[0-9]+$ && "$cgroup_limit" -lt 274877906944 ]]; then  # 256GB
                total=$((cgroup_limit / 1024))  # 转换为KB
                used=$((cgroup_usage / 1024))   # 转换为KB
                free=$((total - used))
            fi
        fi

        # 确保所有值都是有效数字
        total=$(sanitize_integer "$total" "0")
        used=$(sanitize_integer "$used" "0")
        free=$(sanitize_integer "$free" "0")

        # 如果仍然没有获取到数据，设置默认值
        if [[ "$total" == "0" ]]; then
            total=0
            used=0
            free=0
        fi
    fi

    if [[ $total -gt 0 ]]; then
        usage_percent=$(echo "scale=1; $used * 100 / $total" | bc 2>/dev/null || echo "0")
        # 确保usage_percent是有效的数字
        if ! [[ "$usage_percent" =~ ^[0-9]+\.?[0-9]*$ ]]; then
            usage_percent="0"
        fi
    else
        usage_percent="0"
    fi

    echo "{\"total\":$total,\"used\":$used,\"free\":$free,\"usage_percent\":$usage_percent}"
}

# 获取磁盘使用情况
get_disk_usage() {
    local total used free usage_percent

    # 多种方法获取磁盘信息，提高兼容性
    if command_exists df; then
        # 使用-k参数确保输出单位一致（KB）
        local disk_info=$(df -k / 2>/dev/null | tail -1)
        if [[ -n "$disk_info" ]]; then
            # 从KB转换为GB，使用awk进行更安全的计算
            total=$(echo "$disk_info" | awk '{printf "%.2f", $2 / 1024 / 1024}' 2>/dev/null || echo "0")
            used=$(echo "$disk_info" | awk '{printf "%.2f", $3 / 1024 / 1024}' 2>/dev/null || echo "0")
            free=$(echo "$disk_info" | awk '{printf "%.2f", $4 / 1024 / 1024}' 2>/dev/null || echo "0")
            usage_percent=$(echo "$disk_info" | awk '{print $5}' | tr -d '%' 2>/dev/null || echo "0")

            # 验证数据有效性
            total=$(sanitize_number "$total" "0")
            used=$(sanitize_number "$used" "0")
            free=$(sanitize_number "$free" "0")
            usage_percent=$(sanitize_integer "$usage_percent" "0")
        else
            total="0"
            used="0"
            free="0"
            usage_percent="0"
        fi
    else
        # 如果df不可用，尝试其他方法
        total="0"
        used="0"
        free="0"
        usage_percent="0"
    fi

    # 容器环境特殊处理
    if [[ "$CONTAINER_ENV" == "true" && "$total" == "0" ]]; then
        # 在容器中，尝试获取当前目录的磁盘使用情况
        if command_exists df; then
            local container_disk=$(df -k . 2>/dev/null | tail -1)
            if [[ -n "$container_disk" ]]; then
                total=$(echo "$container_disk" | awk '{printf "%.2f", $2 / 1024 / 1024}' 2>/dev/null || echo "0")
                used=$(echo "$container_disk" | awk '{printf "%.2f", $3 / 1024 / 1024}' 2>/dev/null || echo "0")
                free=$(echo "$container_disk" | awk '{printf "%.2f", $4 / 1024 / 1024}' 2>/dev/null || echo "0")
                usage_percent=$(echo "$container_disk" | awk '{print $5}' | tr -d '%' 2>/dev/null || echo "0")

                total=$(sanitize_number "$total" "0")
                used=$(sanitize_number "$used" "0")
                free=$(sanitize_number "$free" "0")
                usage_percent=$(sanitize_integer "$usage_percent" "0")
            fi
        fi
    fi

    echo "{\"total\":$total,\"used\":$used,\"free\":$free,\"usage_percent\":$usage_percent}"
}

# 获取网络使用情况
get_network_usage() {
    local upload_speed=0
    local download_speed=0
    local total_upload=0
    local total_download=0

    # FreeBSD系统
    if [[ "$OS" == "FreeBSD" ]]; then
        # 获取默认网络接口
        local interface=""

        # FreeBSD使用不同的route命令格式
        if command_exists route; then
            # 获取默认路由的接口
            interface=$(route -n get default 2>/dev/null | grep 'interface:' | awk '{print $2}')
        fi

        # 如果没有找到，尝试查找活跃接口
        if [[ -z "$interface" ]] && command_exists netstat; then
            # 查找有流量的接口（排除lo）
            interface=$(netstat -i -b | awk 'NR>1 && $1 !~ /^lo/ && ($7 > 0 || $10 > 0) {print $1; exit}')
        fi

        # 如果还是没找到，使用第一个非lo接口
        if [[ -z "$interface" ]] && command_exists ifconfig; then
            interface=$(ifconfig -l | tr ' ' '\n' | grep -v '^lo' | head -1)
        fi

        if [[ -n "$interface" ]] && command_exists netstat; then
            # 使用netstat获取网络统计
            # FreeBSD netstat -i -b 输出格式：
            # Name  Mtu Network       Address              Ipkts Ierrs Idrop     Ibytes    Opkts Oerrs     Obytes  Coll
            # 同一接口可能有多行，我们只取第一行（Link层的统计）
            local net_stats=$(netstat -i -b 2>/dev/null | grep "^$interface" | grep "<Link#" | head -1 2>/dev/null || echo "")
            if [[ -n "$net_stats" ]]; then
                local raw_download=$(echo "$net_stats" | awk '{print $8}' 2>/dev/null || echo "0")  # Ibytes
                local raw_upload=$(echo "$net_stats" | awk '{print $11}' 2>/dev/null || echo "0")   # Obytes

                # 清理和验证数值
                total_download=$(sanitize_integer "$raw_download" "0")
                total_upload=$(sanitize_integer "$raw_upload" "0")
            else
                # 如果没有找到Link统计，尝试其他方法
                local net_stats_alt=$(netstat -i -b 2>/dev/null | grep "^$interface" | head -1 2>/dev/null || echo "")
                if [[ -n "$net_stats_alt" ]]; then
                    local raw_download=$(echo "$net_stats_alt" | awk '{print $8}' 2>/dev/null || echo "0")
                    local raw_upload=$(echo "$net_stats_alt" | awk '{print $11}' 2>/dev/null || echo "0")
                    total_download=$(sanitize_integer "$raw_download" "0")
                    total_upload=$(sanitize_integer "$raw_upload" "0")
                fi
            fi

            # 计算速度（简单方法）
            local speed_file="/tmp/vps_monitor_net_${interface}"
            local current_time=$(date +%s)

            if [[ -f "$speed_file" ]]; then
                local last_data=$(cat "$speed_file")
                local last_time=$(echo "$last_data" | cut -d' ' -f1)
                local last_rx=$(echo "$last_data" | cut -d' ' -f2)
                local last_tx=$(echo "$last_data" | cut -d' ' -f3)

                local time_diff=$((current_time - last_time))
                if [[ $time_diff -gt 0 ]]; then
                    download_speed=$(( (total_download - last_rx) / time_diff ))
                    upload_speed=$(( (total_upload - last_tx) / time_diff ))

                    # 确保速度不为负数
                    [[ $download_speed -lt 0 ]] && download_speed=0
                    [[ $upload_speed -lt 0 ]] && upload_speed=0
                fi
            fi

            # 保存当前数据供下次使用
            echo "$current_time $total_download $total_upload" > "$speed_file"
        fi
    else
        # Linux系统
        # 获取默认网络接口 - 多种方法提高兼容性
        local interface=""

        # 方法1: 使用ip命令（现代Linux）
        if command_exists ip; then
            interface=$(ip route show default 2>/dev/null | awk '/default/ {print $5}' | head -1)
        fi

        # 方法2: 使用route命令（传统方法）
        if [[ -z "$interface" ]] && command_exists route; then
            interface=$(route -n 2>/dev/null | awk '/^0.0.0.0/ {print $8}' | head -1)
        fi

        # 方法3: 检查/proc/net/route（直接读取内核路由表）
        if [[ -z "$interface" && -f "/proc/net/route" ]]; then
            interface=$(awk '/^[^I]/ && $2 == "00000000" {print $1; exit}' /proc/net/route 2>/dev/null)
        fi

        # 方法4: 查找活跃的网络接口
        if [[ -z "$interface" && -f "/proc/net/dev" ]]; then
            # 查找有流量的接口（排除lo和虚拟接口）
            interface=$(awk '/^ *[^:]*:/ {
                gsub(/:/, "", $1)
                if ($1 != "lo" && $1 !~ /^(docker|br-|veth|tun|tap)/ && ($2 > 0 || $10 > 0)) {
                    print $1
                    exit
                }
            }' /proc/net/dev)
        fi

        # 方法5: 如果还是没找到，使用第一个非lo接口
        if [[ -z "$interface" && -f "/proc/net/dev" ]]; then
            interface=$(awk '/^ *[^:]*:/ {
                gsub(/:/, "", $1)
                if ($1 != "lo" && $1 !~ /^(docker|br-|veth|tun|tap)/) {
                    print $1
                    exit
                }
            }' /proc/net/dev)
        fi

        if [[ -n "$interface" && -f "/proc/net/dev" ]]; then
            # 获取总流量
            local net_line=$(grep "^ *$interface:" /proc/net/dev 2>/dev/null)
            if [[ -n "$net_line" ]]; then
                # 解析网络统计数据
                # 格式: interface: bytes packets errs drop fifo frame compressed multicast
                local stats=($net_line)
                total_download=${stats[1]}  # 接收字节数
                total_upload=${stats[9]}    # 发送字节数

                # 确保是数字
                if ! [[ "$total_download" =~ ^[0-9]+$ ]]; then
                    total_download=0
                fi
                if ! [[ "$total_upload" =~ ^[0-9]+$ ]]; then
                    total_upload=0
                fi
            fi

            # 尝试获取实时速度
            if command_exists ifstat && [[ -n "$interface" ]]; then
                # 使用ifstat获取实时速度
                local network_speed=$(timeout 3 ifstat -i "$interface" 1 1 2>/dev/null | tail -1)
                if [[ -n "$network_speed" && "$network_speed" != *"no statistics"* ]]; then
                    download_speed=$(echo "$network_speed" | awk '{printf "%.0f", $1 * 1024}' 2>/dev/null || echo "0")
                    upload_speed=$(echo "$network_speed" | awk '{printf "%.0f", $2 * 1024}' 2>/dev/null || echo "0")
                fi
            else
                # 如果没有ifstat，使用简单的方法计算速度
                local speed_file="/tmp/vps_monitor_net_${interface}"
                local current_time=$(date +%s)

                if [[ -f "$speed_file" ]]; then
                    local last_data=$(cat "$speed_file")
                    local last_time=$(echo "$last_data" | cut -d' ' -f1)
                    local last_rx=$(echo "$last_data" | cut -d' ' -f2)
                    local last_tx=$(echo "$last_data" | cut -d' ' -f3)

                    local time_diff=$((current_time - last_time))
                    if [[ $time_diff -gt 0 ]]; then
                        download_speed=$(( (total_download - last_rx) / time_diff ))
                        upload_speed=$(( (total_upload - last_tx) / time_diff ))
                    fi
                fi

                # 保存当前数据供下次使用
                echo "$current_time $total_download $total_upload" > "$speed_file"
            fi
        fi
    fi

    # 确保所有值都是数字
    [[ "$upload_speed" =~ ^[0-9]+$ ]] || upload_speed=0
    [[ "$download_speed" =~ ^[0-9]+$ ]] || download_speed=0
    [[ "$total_upload" =~ ^[0-9]+$ ]] || total_upload=0
    [[ "$total_download" =~ ^[0-9]+$ ]] || total_download=0

    echo "{\"upload_speed\":$upload_speed,\"download_speed\":$download_speed,\"total_upload\":$total_upload,\"total_download\":$total_download}"
}

# 获取系统运行时间
get_uptime() {
    local uptime_seconds=0

    # FreeBSD系统
    if [[ "$OS" == "FreeBSD" ]]; then
        if command_exists sysctl; then
            # FreeBSD使用sysctl获取启动时间
            local boot_time_raw=$(sysctl -n kern.boottime 2>/dev/null | awk '{print $4}' | tr -d ',' 2>/dev/null || echo "0")
            local boot_time=$(sanitize_integer "$boot_time_raw" "0")
            local current_time=$(date +%s)

            if [[ $boot_time -gt 0 && $current_time -gt $boot_time ]]; then
                uptime_seconds=$((current_time - boot_time))
            else
                # 如果无法获取启动时间，尝试其他方法
                if command_exists uptime; then
                    # 尝试解析uptime命令输出
                    local uptime_str=$(uptime 2>/dev/null | grep -o 'up [^,]*' | sed 's/up //' || echo "0")
                    # 简化处理，假设格式为 "X days" 或 "X:Y"
                    if [[ "$uptime_str" =~ ([0-9]+).*day ]]; then
                        uptime_seconds=$((${BASH_REMATCH[1]} * 86400))
                    else
                        uptime_seconds=0
                    fi
                else
                    uptime_seconds=0
                fi
            fi
        else
            uptime_seconds=0
        fi
    else
        # Linux系统
        if [[ -f /proc/uptime ]]; then
            uptime_seconds=$(cut -d. -f1 /proc/uptime)
        elif command_exists uptime; then
            # 解析uptime命令输出
            local uptime_str=$(uptime | awk '{print $3}')
            # 这里简化处理，实际可能需要更复杂的解析
            uptime_seconds=$(echo "$uptime_str" | sed 's/,//' | awk '{print $1 * 86400}' 2>/dev/null || echo "0")
        fi
    fi

    echo "$uptime_seconds"
}

# 验证和清理数值
sanitize_number() {
    local value="$1"
    local default_value="${2:-0}"

    # 移除所有非数字和小数点的字符
    value=$(echo "$value" | sed 's/[^0-9.]//g')

    # 检查是否为有效数字
    if [[ "$value" =~ ^[0-9]+\.?[0-9]*$ ]] || [[ "$value" =~ ^[0-9]*\.[0-9]+$ ]]; then
        # 确保小数点前有数字（修复.2变成0.2）
        if [[ "$value" =~ ^\. ]]; then
            value="0$value"
        fi
        # 确保小数点后有数字（修复2.变成2.0）
        if [[ "$value" =~ \.$ ]]; then
            value="${value}0"
        fi
        echo "$value"
    else
        echo "$default_value"
    fi
}

# 验证和清理整数
sanitize_integer() {
    local value="$1"
    local default_value="${2:-0}"

    # 移除所有非数字字符
    value=$(echo "$value" | sed 's/[^0-9]//g')

    # 检查是否为有效整数
    if [[ "$value" =~ ^[0-9]+$ ]]; then
        echo "$value"
    else
        echo "$default_value"
    fi
}



# 清理JSON字符串
clean_json_string() {
    local input="$1"
    # 移除可能的控制字符和非打印字符
    echo "$input" | tr -d '\000-\037' | tr -d '\177-\377'
}

# 上报监控数据
report_metrics() {
    local timestamp=$(date +%s)
    local cpu_raw=$(get_cpu_usage)
    local memory_raw=$(get_memory_usage)
    local disk_raw=$(get_disk_usage)
    local network_raw=$(get_network_usage)
    local uptime_raw=$(get_uptime)

    # 验证运行时间
    local uptime=$(sanitize_integer "$uptime_raw" "0")

    # 清理JSON数据
    cpu_raw=$(clean_json_string "$cpu_raw")
    memory_raw=$(clean_json_string "$memory_raw")
    disk_raw=$(clean_json_string "$disk_raw")
    network_raw=$(clean_json_string "$network_raw")

    # 验证各个JSON组件（使用更宽松的验证）
    if [[ -z "$cpu_raw" || "$cpu_raw" == "{}" || ! "$cpu_raw" =~ ^\{.*\}$ ]]; then
        log "使用默认CPU数据"
        cpu_raw='{"usage_percent":0,"load_avg":[0,0,0]}'
    fi
    if [[ -z "$memory_raw" || "$memory_raw" == "{}" || ! "$memory_raw" =~ ^\{.*\}$ ]]; then
        log "使用默认内存数据"
        memory_raw='{"total":0,"used":0,"free":0,"usage_percent":0}'
    fi
    if [[ -z "$disk_raw" || "$disk_raw" == "{}" || ! "$disk_raw" =~ ^\{.*\}$ ]]; then
        log "使用默认磁盘数据"
        disk_raw='{"total":0,"used":0,"free":0,"usage_percent":0}'
    fi
    if [[ -z "$network_raw" || "$network_raw" == "{}" || ! "$network_raw" =~ ^\{.*\}$ ]]; then
        log "使用默认网络数据"
        network_raw='{"upload_speed":0,"download_speed":0,"total_upload":0,"total_download":0}'
    fi

    # 构建JSON数据
    local data="{\"timestamp\":$timestamp,\"cpu\":$cpu_raw,\"memory\":$memory_raw,\"disk\":$disk_raw,\"network\":$network_raw,\"uptime\":$uptime}"

    log "正在上报数据到 $WORKER_URL/api/report/$SERVER_ID"

    local response=$(curl -s -w "%{http_code}" -X POST "$WORKER_URL/api/report/$SERVER_ID" \
        -H "Content-Type: application/json" \
        -H "X-API-Key: $API_KEY" \
        -d "$data" 2>/dev/null || echo "000")

    local http_code="${response: -3}"
    local response_body="${response%???}"

    if [[ "$http_code" == "200" ]]; then
        log "数据上报成功"

        # 尝试从响应中解析新的间隔设置
        if command_exists jq; then
            # 如果有jq命令，使用jq解析
            local new_interval=$(echo "$response_body" | jq -r '.interval // empty' 2>/dev/null)
            if [[ -n "$new_interval" && "$new_interval" =~ ^[0-9]+$ && "$new_interval" -gt 0 ]]; then
                if [[ "$new_interval" != "$INTERVAL" ]]; then
                    log "服务器返回新的上报间隔: ${new_interval}秒 (当前: ${INTERVAL}秒)"
                    INTERVAL="$new_interval"
                    # 更新配置文件
                    save_config
                    log "上报间隔已更新为: ${INTERVAL}秒"
                    # 创建重启标记文件，让主循环重启服务以应用新间隔
                    touch "$SCRIPT_DIR/restart_needed"
                fi
            fi
        else
            # 如果没有jq，使用简单的文本解析
            local new_interval=$(echo "$response_body" | sed -n 's/.*"interval":\([0-9]\+\).*/\1/p')
            if [[ -n "$new_interval" && "$new_interval" =~ ^[0-9]+$ && "$new_interval" -gt 0 ]]; then
                if [[ "$new_interval" != "$INTERVAL" ]]; then
                    log "服务器返回新的上报间隔: ${new_interval}秒 (当前: ${INTERVAL}秒)"
                    INTERVAL="$new_interval"
                    # 更新配置文件
                    save_config
                    log "上报间隔已更新为: ${INTERVAL}秒"
                    # 创建重启标记文件，让主循环重启服务以应用新间隔
                    touch "$SCRIPT_DIR/restart_needed"
                fi
            fi
        fi

        return 0
    else
        log "数据上报失败 (HTTP $http_code): $response_body"

        # 简化的错误处理
        case "$http_code" in
            "400") log "数据格式错误" ;;
            "401") log "认证失败 - 请检查API密钥" ;;
            "404") log "服务器不存在 - 请检查服务器ID" ;;
            "429") log "请求过于频繁 - 将自动重试" ;;
            "500"|"503") log "服务器错误 - 将在下个周期重试" ;;
            "000") log "网络连接失败" ;;
            *) log "未知错误 (HTTP $http_code)" ;;
        esac

        return 1
    fi
}

# 创建监控服务脚本
create_service_script() {
    # 获取当前脚本的绝对路径
    local main_script_path=$(realpath "$0")

    cat > "$SERVICE_FILE" << EOF
#!/bin/bash

# cf-vps-monitor服务脚本 - 匹配最新worker.js
SCRIPT_DIR="$HOME/.cf-vps-monitor"
CONFIG_FILE="\$SCRIPT_DIR/config"
LOG_FILE="\$SCRIPT_DIR/monitor.log"
PID_FILE="\$SCRIPT_DIR/monitor.pid"
MAIN_SCRIPT="$main_script_path"

# 加载配置
if [[ -f "\$CONFIG_FILE" ]]; then
    source "\$CONFIG_FILE"
else
    echo "配置文件不存在: \$CONFIG_FILE"
    exit 1
fi

# 日志函数
log() {
    local message="\$1"
    local timestamp=\$(date '+%Y-%m-%d %H:%M:%S')
    echo "[\$timestamp] \$message" >> "\$LOG_FILE"
}

# 从主脚本加载监控函数
source_monitoring_functions() {
    # 提取主脚本中的监控函数
    if [[ -f "\$MAIN_SCRIPT" ]]; then
        # 临时文件包含所需的函数（使用用户可写目录）
        local temp_dir="\${TMPDIR:-\${HOME}/.cache}"
        mkdir -p "\$temp_dir" 2>/dev/null || temp_dir="\$SCRIPT_DIR"
        local temp_functions="\$temp_dir/vps_monitor_functions_\$\$.sh"

        # 提取需要的函数和变量
        awk '
        /^# 检测系统信息/,/^}/ { if (/^}/) print; else print; next }
        /^# 获取CPU使用率/,/^}/ { if (/^}/) print; else print; next }
        /^# 获取内存使用情况/,/^}/ { if (/^}/) print; else print; next }
        /^# 获取磁盘使用情况/,/^}/ { if (/^}/) print; else print; next }
        /^# 获取网络使用情况/,/^}/ { if (/^}/) print; else print; next }
        /^# 获取系统运行时间/,/^}/ { if (/^}/) print; else print; next }
        /^# 验证和清理数值/,/^}/ { if (/^}/) print; else print; next }
        /^# 验证和清理整数/,/^}/ { if (/^}/) print; else print; next }

        /^command_exists\(\)/ { print; getline; print; getline; print; next }
        ' "\$MAIN_SCRIPT" > "\$temp_functions"

        # 添加系统检测
        echo 'OS=\$(uname -s)' >> "\$temp_functions"
        echo 'export OS' >> "\$temp_functions"

        source "\$temp_functions"
        rm -f "\$temp_functions"
    else
        log "错误: 找不到主脚本 \$MAIN_SCRIPT"
        exit 1
    fi
}

# 加载监控函数
source_monitoring_functions

# 清理JSON字符串
clean_json_string() {
    local input="\$1"
    # 移除可能的控制字符和非打印字符
    echo "\$input" | tr -d '\\000-\\037' | tr -d '\\177-\\377'
}

# 上报监控数据
report_metrics() {
    local timestamp=\$(date +%s)
    local cpu_raw=\$(get_cpu_usage)
    local memory_raw=\$(get_memory_usage)
    local disk_raw=\$(get_disk_usage)
    local network_raw=\$(get_network_usage)
    local uptime_raw=\$(get_uptime)

    # 验证运行时间
    local uptime=\$(sanitize_integer "\$uptime_raw" "0")

    # 清理JSON数据
    cpu_raw=\$(clean_json_string "\$cpu_raw")
    memory_raw=\$(clean_json_string "\$memory_raw")
    disk_raw=\$(clean_json_string "\$disk_raw")
    network_raw=\$(clean_json_string "\$network_raw")

    # 验证各个JSON组件（使用更宽松的验证）
    if [[ -z "\$cpu_raw" || "\$cpu_raw" == "{}" || ! "\$cpu_raw" =~ ^\{.*\}\$ ]]; then
        cpu_raw='{\\"usage_percent\\":0,\\"load_avg\\":[0,0,0]}'
    fi
    if [[ -z "\$memory_raw" || "\$memory_raw" == "{}" || ! "\$memory_raw" =~ ^\{.*\}\$ ]]; then
        memory_raw='{\\"total\\":0,\\"used\\":0,\\"free\\":0,\\"usage_percent\\":0}'
    fi
    if [[ -z "\$disk_raw" || "\$disk_raw" == "{}" || ! "\$disk_raw" =~ ^\{.*\}\$ ]]; then
        disk_raw='{\\"total\\":0,\\"used\\":0,\\"free\\":0,\\"usage_percent\\":0}'
    fi
    if [[ -z "\$network_raw" || "\$network_raw" == "{}" || ! "\$network_raw" =~ ^\{.*\}\$ ]]; then
        network_raw='{\\"upload_speed\\":0,\\"download_speed\\":0,\\"total_upload\\":0,\\"total_download\\":0}'
    fi

    # 构建JSON数据
    local data="{\\"timestamp\\":\$timestamp,\\"cpu\\":\$cpu_raw,\\"memory\\":\$memory_raw,\\"disk\\":\$disk_raw,\\"network\\":\$network_raw,\\"uptime\\":\$uptime}"

    log "正在上报数据..."

    local response=\$(curl -s -w "%{http_code}" -X POST "\$WORKER_URL/api/report/\$SERVER_ID" \\
        -H "Content-Type: application/json" \\
        -H "X-API-Key: \$API_KEY" \\
        -d "\$data" 2>/dev/null || echo "000")

    local http_code="\${response: -3}"
    local response_body="\${response%???}"

    if [[ "\$http_code" == "200" ]]; then
        log "数据上报成功"

        # 尝试从响应中解析新的间隔设置
        # 使用简单的文本解析（避免依赖jq）
        local new_interval=\$(echo "\$response_body" | sed -n 's/.*"interval":\\([0-9]\\+\\).*/\\1/p')
        if [[ -n "\$new_interval" && "\$new_interval" =~ ^[0-9]+\$ && "\$new_interval" -gt 0 ]]; then
            if [[ "\$new_interval" != "\$INTERVAL" ]]; then
                log "服务器返回新的上报间隔: \${new_interval}秒 (当前: \${INTERVAL}秒)"
                INTERVAL="\$new_interval"
                # 更新配置文件
                cat > "\$CONFIG_FILE" << EOL
# VPS监控配置文件
WORKER_URL="\$WORKER_URL"
SERVER_ID="\$SERVER_ID"
API_KEY="\$API_KEY"
INTERVAL="\$INTERVAL"
EOL
                log "上报间隔已更新为: \${INTERVAL}秒"
                # 创建重启标记文件，让主循环重新加载配置
                touch "\$SCRIPT_DIR/restart_needed"
            fi
        fi

        return 0
    else
        log "数据上报失败 (HTTP \$http_code): \$response_body"

        # 简化的错误处理
        case "\$http_code" in
            "400") log "数据格式错误" ;;
            "401") log "认证失败 - 请检查API密钥" ;;
            "404") log "服务器不存在 - 请检查服务器ID" ;;
            "429") log "请求过于频繁 - 将自动重试" ;;
            "500"|"503") log "服务器错误 - 将在下个周期重试" ;;
            "000") log "网络连接失败" ;;
            *) log "未知错误 (HTTP \$http_code)" ;;
        esac

        return 1
    fi
}

# 主循环
main() {
    log "VPS监控服务启动 (PID: \$\$)"
    echo \$\$ > "\$PID_FILE"

    # 信号处理
    trap 'log "收到终止信号，正在停止..."; rm -f "\$PID_FILE"; exit 0' TERM INT

    while true; do
        if ! report_metrics; then
            log "上报失败，将在下个周期重试"
        fi

        # 检查是否需要重启以应用新的间隔设置
        if [[ -f "\$SCRIPT_DIR/restart_needed" ]]; then
            log "检测到间隔设置变更，正在重新加载配置..."
            rm -f "\$SCRIPT_DIR/restart_needed"
            # 重新加载配置
            if [[ -f "\$CONFIG_FILE" ]]; then
                source "\$CONFIG_FILE"
                log "已重新加载配置，新的上报间隔: \${INTERVAL}秒"
            fi
        fi

        sleep "\$INTERVAL"
    done
}

# 启动主函数
main
EOF

    chmod +x "$SERVICE_FILE"
    print_message "$GREEN" "监控服务脚本创建完成: $SERVICE_FILE"
}

# 创建systemd用户服务
create_systemd_service() {
    if ! command_exists systemctl; then
        print_message "$YELLOW" "systemd不可用，将使用传统方式运行服务"
        return 1
    fi

    # 检查是否可以使用systemd用户服务
    if ! systemctl --user status >/dev/null 2>&1; then
        print_message "$YELLOW" "systemd用户服务不可用，将使用传统方式运行服务"
        return 1
    fi

    # 确保systemd服务文件目录存在
    local systemd_dir=$(dirname "$SYSTEMD_SERVICE_FILE")
    if [[ ! -d "$systemd_dir" ]]; then
        if ! mkdir -p "$systemd_dir" 2>/dev/null; then
            print_message "$YELLOW" "无法创建systemd目录，将使用传统方式运行服务"
            return 1
        fi
    fi

    cat > "$SYSTEMD_SERVICE_FILE" << EOF
[Unit]
Description=cf-vps-monitor Service
After=network.target

[Service]
Type=simple
ExecStart=$SERVICE_FILE
Restart=always
RestartSec=10
User=$USER
WorkingDirectory=$SCRIPT_DIR
Environment=HOME=$HOME
Environment=PATH=$PATH

[Install]
WantedBy=default.target
EOF

    # 重新加载systemd配置
    if ! systemctl --user daemon-reload 2>/dev/null; then
        print_message "$YELLOW" "无法重新加载systemd配置，将使用传统方式运行服务"
        return 1
    fi

    print_message "$GREEN" "systemd用户服务创建完成: $SYSTEMD_SERVICE_FILE"
    return 0
}

# 启动监控服务
start_service() {
    if [[ -f "$PID_FILE" ]]; then
        local pid=$(cat "$PID_FILE")
        if kill -0 "$pid" 2>/dev/null; then
            print_message "$YELLOW" "监控服务已在运行 (PID: $pid)"
            return 0
        else
            rm -f "$PID_FILE"
        fi
    fi

    # 尝试使用systemd
    if [[ -f "$SYSTEMD_SERVICE_FILE" ]] && command_exists systemctl; then
        print_message "$BLUE" "使用systemd启动服务..."
        if systemctl --user start cf-vps-monitor.service; then
            systemctl --user enable cf-vps-monitor.service
            print_message "$GREEN" "监控服务已启动 (systemd)"
            return 0
        else
            print_message "$YELLOW" "systemd启动失败，尝试传统方式"
        fi
    fi

    # 传统方式启动
    print_message "$BLUE" "使用传统方式启动服务..."

    # 确保服务脚本可执行
    chmod +x "$SERVICE_FILE" 2>/dev/null || true

    # 启动后台服务，重定向到日志文件
    if command_exists nohup; then
        nohup "$SERVICE_FILE" >> "$LOG_FILE" 2>&1 &
    else
        "$SERVICE_FILE" >> "$LOG_FILE" 2>&1 &
    fi

    local pid=$!
    echo "$pid" > "$PID_FILE"

    # 等待一下检查是否启动成功
    sleep 2
    if kill -0 "$pid" 2>/dev/null; then
        print_message "$GREEN" "监控服务已启动 (传统方式, PID: $pid)"
        print_message "$CYAN" "日志文件: $LOG_FILE"
        return 0
    else
        print_message "$RED" "监控服务启动失败"
        if [[ -f "$LOG_FILE" ]]; then
            print_message "$YELLOW" "查看日志获取错误信息: tail -f $LOG_FILE"
        fi
        rm -f "$PID_FILE"
        return 1
    fi
}

# 停止监控服务
stop_service() {
    print_message "$BLUE" "停止监控服务..."

    local stopped=false

    # 尝试使用systemd停止
    if [[ -f "$SYSTEMD_SERVICE_FILE" ]] && command_exists systemctl; then
        if systemctl --user is-active cf-vps-monitor.service >/dev/null 2>&1; then
            systemctl --user stop cf-vps-monitor.service
            systemctl --user disable cf-vps-monitor.service
            stopped=true
            print_message "$GREEN" "监控服务已停止 (systemd)"
        fi
    fi

    # 传统方式停止
    if [[ -f "$PID_FILE" ]]; then
        local pid=$(cat "$PID_FILE")
        if kill -0 "$pid" 2>/dev/null; then
            kill "$pid"
            sleep 2
            if kill -0 "$pid" 2>/dev/null; then
                kill -9 "$pid"
            fi
            stopped=true
            print_message "$GREEN" "监控服务已停止 (PID: $pid)"
        fi
        rm -f "$PID_FILE"
    fi

    if [[ "$stopped" == "false" ]]; then
        print_message "$YELLOW" "没有发现运行中的监控服务"
    fi
}

# 检查服务状态
check_service_status() {
    print_message "$BLUE" "检查监控服务状态..."

    local running=false

    # 检查systemd状态
    if [[ -f "$SYSTEMD_SERVICE_FILE" ]] && command_exists systemctl; then
        if systemctl --user is-active cf-vps-monitor.service >/dev/null 2>&1; then
            print_message "$GREEN" "✓ systemd服务运行中"
            systemctl --user status cf-vps-monitor.service --no-pager -l
            running=true
        else
            print_message "$YELLOW" "✗ systemd服务未运行"
        fi
    fi

    # 检查PID文件
    if [[ -f "$PID_FILE" ]]; then
        local pid=$(cat "$PID_FILE")
        if kill -0 "$pid" 2>/dev/null; then
            print_message "$GREEN" "✓ 监控进程运行中 (PID: $pid)"
            running=true
        else
            print_message "$YELLOW" "✗ PID文件存在但进程不存在"
            rm -f "$PID_FILE"
        fi
    else
        print_message "$YELLOW" "✗ 没有PID文件"
    fi

    if [[ "$running" == "false" ]]; then
        print_message "$RED" "监控服务未运行"
    fi

    # 显示配置信息
    echo
    print_message "$CYAN" "配置信息:"
    if [[ -f "$CONFIG_FILE" ]]; then
        load_config
        echo "  Worker URL: $WORKER_URL"
        echo "  Server ID: $SERVER_ID"
        echo "  API Key: ${API_KEY:0:8}..."
        echo "  上报间隔: ${INTERVAL}秒"
    else
        print_message "$YELLOW" "  配置文件不存在"
    fi
}

# 查看日志
view_logs() {
    if [[ ! -f "$LOG_FILE" ]]; then
        print_message "$YELLOW" "日志文件不存在: $LOG_FILE"
        return
    fi

    print_message "$BLUE" "显示最近50行日志:"
    echo "----------------------------------------"
    tail -n 50 "$LOG_FILE"
    echo "----------------------------------------"
    print_message "$CYAN" "日志文件位置: $LOG_FILE"
}

# 测试连接
test_connection() {
    print_message "$BLUE" "测试连接到监控服务器..."

    load_config

    if [[ -z "$WORKER_URL" || -z "$SERVER_ID" || -z "$API_KEY" ]]; then
        print_message "$RED" "配置不完整，请先配置监控参数"
        return 1
    fi

    print_message "$BLUE" "正在测试上报数据..."
    if report_metrics; then
        print_message "$GREEN" "✓ 连接测试成功"
    else
        print_message "$RED" "✗ 连接测试失败，请检查配置和网络"
        return 1
    fi
}







# 配置监控参数
configure_monitor() {
    print_message "$BLUE" "配置监控参数"
    echo

    load_config

    # Server ID
    echo -n "请输入Server ID"
    if [[ -n "$SERVER_ID" ]]; then
        echo -n " (当前: $SERVER_ID)"
    fi
    echo -n ": "
    read -r input_server_id
    if [[ -n "$input_server_id" ]]; then
        SERVER_ID="$input_server_id"
    fi

    # API Key
    echo -n "请输入API Key"
    if [[ -n "$API_KEY" ]]; then
        echo -n " (当前: ${API_KEY:0:8}...)"
    fi
    echo -n ": "
    read -r input_api_key
    if [[ -n "$input_api_key" ]]; then
        API_KEY="$input_api_key"
    fi

    # Worker URL
    echo -n "请输入Worker URL"
    if [[ -n "$WORKER_URL" ]]; then
        echo -n " (当前: $WORKER_URL)"
    fi
    echo -n ": "
    read -r input_url
    if [[ -n "$input_url" ]]; then
        WORKER_URL="$input_url"
    fi

    # 设置默认上报间隔为10秒，脚本会自动从服务器获取最新配置
    if [[ -z "$INTERVAL" ]]; then
        INTERVAL="10"
    fi
    print_message "$CYAN" "上报间隔设置为: ${INTERVAL}秒 (脚本运行后会自动从服务器获取最新配置)"

    # 验证配置
    if [[ -z "$WORKER_URL" || -z "$SERVER_ID" || -z "$API_KEY" ]]; then
        print_message "$RED" "配置不完整，请确保所有必需参数都已填写"
        return 1
    fi

    # 保存配置
    save_config
    print_message "$GREEN" "配置保存成功"

    # 询问是否测试连接
    echo
    echo -n "是否测试连接? (y/N): "
    read -r test_choice
    if [[ "$test_choice" =~ ^[Yy]$ ]]; then
        test_connection
    fi
}

# 安装监控服务
install_monitor() {
    print_message "$BLUE" "开始安装VPS监控服务..."
    echo

    # 检测系统
    detect_system
    detect_package_manager

    # 安装依赖
    install_dependencies

    # 创建目录结构
    create_directories

    # 配置监控参数
    if ! configure_monitor; then
        error_exit "配置失败，安装中止"
    fi

    # 创建服务脚本
    create_service_script

    # 创建systemd服务（如果可用）
    local systemd_available=false
    if create_systemd_service; then
        systemd_available=true
    fi

    # 启动服务
    if start_service; then
        print_message "$GREEN" "✓ VPS监控服务安装并启动成功"
        echo
        print_message "$CYAN" "安装信息:"
        echo "  安装目录: $SCRIPT_DIR"
        echo "  配置文件: $CONFIG_FILE"
        echo "  日志文件: $LOG_FILE"
        echo "  服务脚本: $SERVICE_FILE"
        if [[ "$systemd_available" == "true" ]]; then
            echo "  systemd服务: $SYSTEMD_SERVICE_FILE"
            print_message "$GREEN" "  启动方式: systemd用户服务"
        else
            print_message "$GREEN" "  启动方式: 传统后台进程"
        fi
        echo
        print_message "$YELLOW" "提示: 使用 '$0 status' 检查服务状态"
        print_message "$YELLOW" "提示: 使用 '$0 logs' 查看运行日志"
    else
        error_exit "服务启动失败"
    fi
}

# 彻底卸载监控服务
uninstall_monitor() {
    print_message "$YELLOW" "警告: 这将彻底删除VPS监控服务及其所有数据"
    echo -n "确认卸载? (y/N): "
    read -r confirm

    if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
        print_message "$BLUE" "取消卸载"
        return 0
    fi

    print_message "$BLUE" "开始卸载VPS监控服务..."

    # 停止服务
    stop_service

    # 删除systemd服务
    if [[ -f "$SYSTEMD_SERVICE_FILE" ]] && command_exists systemctl; then
        print_message "$BLUE" "删除systemd服务..."
        systemctl --user disable vps-monitor.service 2>/dev/null || true
        rm -f "$SYSTEMD_SERVICE_FILE"
        systemctl --user daemon-reload 2>/dev/null || true
    fi

    # 删除所有文件
    if [[ -d "$SCRIPT_DIR" ]]; then
        print_message "$BLUE" "删除安装目录..."
        rm -rf "$SCRIPT_DIR"
    fi

    print_message "$GREEN" "✓ VPS监控服务已完全卸载"
    print_message "$CYAN" "感谢使用VPS监控服务"
}

# 显示帮助信息
show_help() {
    echo "VPS监控脚本 v2.0"
    echo
    echo "用法: $0 [选项] [参数]"
    echo
    echo "基本选项:"
    echo "  install     安装监控服务"
    echo "  uninstall   彻底卸载监控服务"
    echo "  start       启动监控服务"
    echo "  stop        停止监控服务"
    echo "  restart     重启监控服务"
    echo "  status      查看服务状态"
    echo "  logs        查看运行日志"
    echo "  config      配置监控参数"
    echo "  test        测试连接"
    echo "  menu        显示交互菜单"
    echo "  help        显示此帮助信息"
    echo
    echo "一键安装参数:"
    echo "  -i, --install           一键安装模式"
    echo "  -s, --server-id ID      服务器ID"
    echo "  -k, --api-key KEY       API密钥"
    echo "  -u, --worker-url URL    Worker地址"
    echo
    echo "示例:"
    echo "  $0 install              # 交互式安装"
    echo "  $0 status               # 查看服务状态"
    echo "  $0 logs                 # 查看日志"
    echo
    echo "一键安装示例:"
    echo "  $0 -i -s server123 -k abc123 -u https://worker.example.com"
    echo
    echo "注意: 上报间隔会自动从服务器获取，无需手动设置"
}

# 显示交互菜单
show_menu() {
    while true; do
        clear
        print_message "$CYAN" "=================================="
        print_message "$CYAN" "       VPS监控服务管理菜单"
        print_message "$CYAN" "=================================="
        echo
        echo "1. 安装监控服务"
        echo "2. 启动监控服务"
        echo "3. 停止监控服务"
        echo "4. 重启监控服务"
        echo "5. 查看服务状态"
        echo "6. 查看运行日志"
        echo "7. 配置监控参数"
        echo "8. 测试连接"
        echo "9. 彻底卸载服务"
        echo "0. 退出"
        echo
        print_message "$YELLOW" "请选择操作 (0-9): "
        read -r choice

        case $choice in
            1)
                echo
                install_monitor
                echo
                print_message "$BLUE" "按任意键继续..."
                read -r
                ;;
            2)
                echo
                start_service
                echo
                print_message "$BLUE" "按任意键继续..."
                read -r
                ;;
            3)
                echo
                stop_service
                echo
                print_message "$BLUE" "按任意键继续..."
                read -r
                ;;
            4)
                echo
                stop_service
                sleep 1
                start_service
                echo
                print_message "$BLUE" "按任意键继续..."
                read -r
                ;;
            5)
                echo
                check_service_status
                echo
                print_message "$BLUE" "按任意键继续..."
                read -r
                ;;
            6)
                echo
                view_logs
                echo
                print_message "$BLUE" "按任意键继续..."
                read -r
                ;;
            7)
                echo
                configure_monitor
                echo
                print_message "$BLUE" "按任意键继续..."
                read -r
                ;;
            8)
                echo
                test_connection
                echo
                print_message "$BLUE" "按任意键继续..."
                read -r
                ;;
            9)
                echo
                uninstall_monitor
                echo
                print_message "$BLUE" "按任意键继续..."
                read -r
                ;;
            0)
                print_message "$GREEN" "感谢使用VPS监控服务！"
                exit 0
                ;;
            *)
                print_message "$RED" "无效选择，请重新输入"
                sleep 1
                ;;
        esac
    done
}

# 解析命令行参数
parse_arguments() {
    local install_mode=false
    local server_id=""
    local api_key=""
    local worker_url=""
    local interval=""

    while [[ $# -gt 0 ]]; do
        case $1 in
            -i|--install)
                install_mode=true
                shift
                ;;
            -s|--server-id)
                server_id="$2"
                shift 2
                ;;
            -k|--api-key)
                api_key="$2"
                shift 2
                ;;
            -u|--worker-url)
                worker_url="$2"
                shift 2
                ;;
            --interval)
                interval="$2"
                shift 2
                ;;
            -h|--help)
                show_help
                exit 0
                ;;
            *)
                # 如果是基本命令，返回处理
                return 1
                ;;
        esac
    done

    # 如果是一键安装模式
    if [[ "$install_mode" == "true" ]]; then
        one_click_install "$server_id" "$api_key" "$worker_url" "$interval"
        exit $?
    fi

    return 1
}

# 一键安装函数
one_click_install() {
    local server_id="$1"
    local api_key="$2"
    local worker_url="$3"
    local interval="${4:-10}"  # 默认10秒，脚本会自动获取服务器配置

    print_message "$BLUE" "开始一键安装VPS监控服务..."
    echo

    # 验证必需参数
    if [[ -z "$server_id" || -z "$api_key" || -z "$worker_url" ]]; then
        print_message "$RED" "错误: 缺少必需参数"
        echo "必需参数: -s <服务器ID> -k <API密钥> -u <Worker地址>"
        echo "使用 '$0 --help' 查看详细帮助"
        return 1
    fi

    # 设置默认间隔为10秒
    interval="10"

    print_message "$CYAN" "安装参数:"
    echo "  服务器ID: $server_id"
    echo "  API密钥: ${api_key:0:8}..."
    echo "  Worker地址: $worker_url"
    echo "  初始上报间隔: ${interval}秒 (运行后会自动从服务器获取最新配置)"
    echo

    # 检测系统
    detect_system
    detect_package_manager

    # 安装依赖
    install_dependencies

    # 创建目录结构
    create_directories

    # 设置配置参数
    WORKER_URL="$worker_url"
    SERVER_ID="$server_id"
    API_KEY="$api_key"
    INTERVAL="$interval"

    # 保存配置
    save_config
    print_message "$GREEN" "配置保存成功"

    # 测试连接
    print_message "$BLUE" "测试连接..."
    if ! report_metrics; then
        print_message "$YELLOW" "警告: 连接测试失败，但将继续安装"
        print_message "$YELLOW" "请检查网络连接和配置参数"
    else
        print_message "$GREEN" "✓ 连接测试成功"
    fi

    # 创建服务脚本
    create_service_script

    # 创建systemd服务（如果可用）
    local systemd_available=false
    if create_systemd_service; then
        systemd_available=true
    fi

    # 启动服务
    if start_service; then
        print_message "$GREEN" "✓ VPS监控服务一键安装成功"
        echo
        print_message "$CYAN" "安装信息:"
        echo "  安装目录: $SCRIPT_DIR"
        echo "  配置文件: $CONFIG_FILE"
        echo "  日志文件: $LOG_FILE"
        echo "  服务脚本: $SERVICE_FILE"
        if [[ "$systemd_available" == "true" ]]; then
            echo "  systemd服务: $SYSTEMD_SERVICE_FILE"
            print_message "$GREEN" "  启动方式: systemd用户服务"
        else
            print_message "$GREEN" "  启动方式: 传统后台进程"
        fi
        echo
        print_message "$YELLOW" "提示: 使用 '$0 status' 检查服务状态"
        print_message "$YELLOW" "提示: 使用 '$0 logs' 查看运行日志"
        return 0
    else
        print_message "$RED" "✗ 服务启动失败"
        return 1
    fi
}

# 主函数
main() {
    # 首先尝试解析命令行参数
    if parse_arguments "$@"; then
        return
    fi

    # 如果没有参数，显示菜单
    if [[ $# -eq 0 ]]; then
        show_menu
        return
    fi

    # 处理命令行参数
    case "$1" in
        install)
            install_monitor
            ;;
        uninstall)
            uninstall_monitor
            ;;
        start)
            start_service
            ;;
        stop)
            stop_service
            ;;
        restart)
            stop_service
            sleep 1
            start_service
            ;;
        status)
            check_service_status
            ;;
        logs)
            view_logs
            ;;
        config)
            configure_monitor
            ;;
        test)
            test_connection
            ;;
        menu)
            show_menu
            ;;
        help|--help|-h)
            show_help
            ;;
        *)
            print_message "$RED" "未知选项: $1"
            echo
            show_help
            exit 1
            ;;
    esac
}

# 脚本入口点
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
