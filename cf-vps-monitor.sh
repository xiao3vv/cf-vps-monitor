#!/bin/bash

# VPS监控脚本 - 支持所有常见Linux系统，无需root权限
# 版本: 2.0
# 作者: VPS Monitor Team

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
SCRIPT_DIR="$HOME/.vps-monitor"
CONFIG_FILE="$SCRIPT_DIR/config"
LOG_FILE="$SCRIPT_DIR/monitor.log"
PID_FILE="$SCRIPT_DIR/monitor.pid"
SERVICE_FILE="$SCRIPT_DIR/monitor-service.sh"
SYSTEMD_SERVICE_FILE="$HOME/.config/systemd/user/vps-monitor.service"

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

    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        OS=$NAME
        VER=$VERSION_ID
    elif command_exists lsb_release; then
        OS=$(lsb_release -si)
        VER=$(lsb_release -sr)
    elif [[ -f /etc/redhat-release ]]; then
        OS="Red Hat Enterprise Linux"
        VER=$(cat /etc/redhat-release | sed 's/.*release //' | sed 's/ .*//')
    else
        VER=$(uname -r)
    fi

    print_message "$CYAN" "检测到系统: $OS $VER"

    # 确保OS变量在全局可用
    export OS
}

# 检测包管理器
detect_package_manager() {
    if [[ "$OS" == "FreeBSD" ]]; then
        if command_exists pkg; then
            PKG_MANAGER="pkg"
            PKG_INSTALL="pkg install -y"
            PKG_UPDATE="pkg update"
        else
            PKG_MANAGER=""
        fi
    elif command_exists apt-get; then
        PKG_MANAGER="apt-get"
        PKG_INSTALL="apt-get install -y"
        PKG_UPDATE="apt-get update"
    elif command_exists yum; then
        PKG_MANAGER="yum"
        PKG_INSTALL="yum install -y"
        PKG_UPDATE="yum update -y"
    elif command_exists dnf; then
        PKG_MANAGER="dnf"
        PKG_INSTALL="dnf install -y"
        PKG_UPDATE="dnf update -y"
    elif command_exists pacman; then
        PKG_MANAGER="pacman"
        PKG_INSTALL="pacman -S --noconfirm"
        PKG_UPDATE="pacman -Sy"
    elif command_exists zypper; then
        PKG_MANAGER="zypper"
        PKG_INSTALL="zypper install -y"
        PKG_UPDATE="zypper refresh"
    elif command_exists apk; then
        PKG_MANAGER="apk"
        PKG_INSTALL="apk add"
        PKG_UPDATE="apk update"
    else
        PKG_MANAGER=""
    fi

    if [[ -n "$PKG_MANAGER" ]]; then
        print_message "$GREEN" "检测到包管理器: $PKG_MANAGER"
    else
        print_message "$YELLOW" "警告: 未检测到支持的包管理器，将尝试手动安装依赖"
    fi
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
    if ! command_exists ifstat; then
        print_message "$YELLOW" "警告: ifstat未安装，网络监控功能将受限"
    fi
    
    if [[ ${#missing_deps[@]} -eq 0 ]]; then
        print_message "$GREEN" "所有必需依赖已安装"
        return 0
    fi
    
    print_message "$YELLOW" "缺少依赖: ${missing_deps[*]}"
    
    # 尝试使用包管理器安装（如果有sudo权限）
    if [[ -n "$PKG_MANAGER" ]] && command_exists sudo; then
        print_message "$BLUE" "尝试使用sudo安装依赖..."
        if sudo -n true 2>/dev/null; then
            for dep in "${missing_deps[@]}"; do
                print_message "$BLUE" "安装 $dep..."
                if ! sudo $PKG_INSTALL "$dep"; then
                    print_message "$YELLOW" "警告: 无法安装 $dep，请手动安装"
                fi
            done
        else
            print_message "$YELLOW" "需要sudo权限安装依赖，或请手动安装: ${missing_deps[*]}"
        fi
    else
        print_message "$YELLOW" "请手动安装以下依赖: ${missing_deps[*]}"
        print_message "$CYAN" "安装命令示例:"
        if [[ -n "$PKG_MANAGER" ]]; then
            print_message "$CYAN" "  sudo $PKG_INSTALL ${missing_deps[*]}"
        fi
    fi
    
    # 再次检查关键依赖
    if ! command_exists curl; then
        error_exit "curl是必需的依赖，请先安装curl"
    fi
    
    if ! command_exists bc; then
        error_exit "bc是必需的依赖，请先安装bc"
    fi
    
    print_message "$GREEN" "依赖检查完成"
}

# 创建目录结构
create_directories() {
    print_message "$BLUE" "创建目录结构..."
    
    mkdir -p "$SCRIPT_DIR"
    mkdir -p "$(dirname "$SYSTEMD_SERVICE_FILE")"
    
    # 创建日志文件
    touch "$LOG_FILE"
    
    print_message "$GREEN" "目录结构创建完成"
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
            local cpu_idle=$(sysctl -n kern.cp_time | awk '{print $5}')
            local cpu_total=$(sysctl -n kern.cp_time | awk '{sum=0; for(i=1;i<=NF;i++) sum+=$i; print sum}')
            if [[ $cpu_total -gt 0 ]]; then
                cpu_usage=$(echo "scale=1; 100 - ($cpu_idle * 100 / $cpu_total)" | bc 2>/dev/null || echo "0")
                # 确保cpu_usage是有效的数字
                if ! [[ "$cpu_usage" =~ ^[0-9]+\.?[0-9]*$ ]]; then
                    cpu_usage="0"
                fi
            else
                cpu_usage="0"
            fi
        else
            cpu_usage="0"
        fi

        # FreeBSD负载平均值
        if command_exists sysctl; then
            local load1=$(sysctl -n vm.loadavg | awk '{print $2}')
            local load5=$(sysctl -n vm.loadavg | awk '{print $3}')
            local load15=$(sysctl -n vm.loadavg | awk '{print $4}')
            cpu_load="$load1,$load5,$load15"
        else
            cpu_load="0,0,0"
        fi
    else
        # Linux系统
        # 使用多种方法获取CPU使用率，提高兼容性
        if command_exists top; then
            cpu_usage=$(top -bn1 | grep -i "cpu(s)" | sed "s/.*, *\([0-9.]*\)%* id.*/\1/" | awk '{print 100 - $1}' 2>/dev/null || echo "0")
        elif [[ -f /proc/stat ]]; then
            # 使用/proc/stat计算CPU使用率
            local cpu_line=$(head -n1 /proc/stat)
            local cpu_times=($cpu_line)
            local idle=${cpu_times[4]}
            local total=0
            for time in "${cpu_times[@]:1:8}"; do
                total=$((total + time))
            done
            cpu_usage=$(echo "scale=1; 100 - ($idle * 100 / $total)" | bc 2>/dev/null || echo "0")
            # 确保cpu_usage是有效的数字
            if ! [[ "$cpu_usage" =~ ^[0-9]+\.?[0-9]*$ ]]; then
                cpu_usage="0"
            fi
        else
            cpu_usage="0"
        fi

        # 获取负载平均值
        if [[ -f /proc/loadavg ]]; then
            cpu_load=$(cat /proc/loadavg | awk '{print $1","$2","$3}')
        else
            cpu_load="0,0,0"
        fi
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
            local page_size=$(sysctl -n hw.pagesize)
            local total_pages=$(sysctl -n vm.stats.vm.v_page_count)
            local free_pages=$(sysctl -n vm.stats.vm.v_free_count)
            local inactive_pages=$(sysctl -n vm.stats.vm.v_inactive_count 2>/dev/null || echo "0")
            local cache_pages=$(sysctl -n vm.stats.vm.v_cache_count 2>/dev/null || echo "0")

            # 计算内存（转换为KB）
            total=$(( (total_pages * page_size) / 1024 ))
            free=$(( ((free_pages + inactive_pages + cache_pages) * page_size) / 1024 ))
            used=$((total - free))
        else
            total=0
            used=0
            free=0
        fi
    else
        # Linux系统
        if command_exists free; then
            local mem_info=$(free -k | grep "^Mem:")
            total=$(echo "$mem_info" | awk '{print $2}')
            used=$(echo "$mem_info" | awk '{print $3}')
            free=$(echo "$mem_info" | awk '{print $4}')
        elif [[ -f /proc/meminfo ]]; then
            total=$(grep "^MemTotal:" /proc/meminfo | awk '{print $2}')
            free=$(grep "^MemFree:" /proc/meminfo | awk '{print $2}')
            used=$((total - free))
        else
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
    
    if command_exists df; then
        local disk_info=$(df -k / 2>/dev/null | tail -1)
        total=$(echo "$disk_info" | awk '{printf "%.2f", $2 / 1024 / 1024}')
        used=$(echo "$disk_info" | awk '{printf "%.2f", $3 / 1024 / 1024}')
        free=$(echo "$disk_info" | awk '{printf "%.2f", $4 / 1024 / 1024}')
        usage_percent=$(echo "$disk_info" | awk '{print $5}' | tr -d '%')
    else
        total="0"
        used="0"
        free="0"
        usage_percent="0"
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
            local net_stats=$(netstat -i -b | grep "^$interface" | grep "<Link#" | head -1)
            if [[ -n "$net_stats" ]]; then
                total_download=$(echo "$net_stats" | awk '{print $8}')  # Ibytes
                total_upload=$(echo "$net_stats" | awk '{print $11}')   # Obytes

                # 确保是数字
                if ! [[ "$total_download" =~ ^[0-9]+$ ]]; then
                    total_download=0
                fi
                if ! [[ "$total_upload" =~ ^[0-9]+$ ]]; then
                    total_upload=0
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
        # 获取默认网络接口
        local interface=""
        if command_exists ip; then
            interface=$(ip route show default 2>/dev/null | awk '/default/ {print $5}' | head -1)
        elif command_exists route; then
            interface=$(route -n 2>/dev/null | awk '/^0.0.0.0/ {print $8}' | head -1)
        fi

        # 如果没有找到默认接口，尝试找到活跃的网络接口
        if [[ -z "$interface" && -f "/proc/net/dev" ]]; then
            # 查找有流量的接口（排除lo）
            interface=$(awk '/^ *[^:]*:/ {
                gsub(/:/, "", $1)
                if ($1 != "lo" && ($2 > 0 || $10 > 0)) {
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
            local boot_time=$(sysctl -n kern.boottime | awk '{print $4}' | tr -d ',')
            local current_time=$(date +%s)
            uptime_seconds=$((current_time - boot_time))
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

# 上报监控数据
report_metrics() {
    local timestamp=$(date +%s)
    local cpu_raw=$(get_cpu_usage)
    local memory_raw=$(get_memory_usage)
    local disk_raw=$(get_disk_usage)
    local network_raw=$(get_network_usage)
    local uptime_raw=$(get_uptime)

    # 解析和验证CPU数据
    local cpu_usage=$(echo "$cpu_raw" | sed -n 's/.*"usage_percent":\([^,}]*\).*/\1/p')
    local cpu_load_raw=$(echo "$cpu_raw" | sed -n 's/.*"load_avg":\[\([^\]]*\)\].*/\1/p')
    cpu_usage=$(sanitize_number "$cpu_usage" "0")

    # 清理CPU负载数组
    local cpu_load=""
    if [[ -n "$cpu_load_raw" ]]; then
        # 分割负载值并验证每个值
        local load1=$(echo "$cpu_load_raw" | cut -d',' -f1)
        local load5=$(echo "$cpu_load_raw" | cut -d',' -f2)
        local load15=$(echo "$cpu_load_raw" | cut -d',' -f3)
        load1=$(sanitize_number "$load1" "0")
        load5=$(sanitize_number "$load5" "0")
        load15=$(sanitize_number "$load15" "0")
        cpu_load="$load1,$load5,$load15"
    else
        cpu_load="0,0,0"
    fi

    # 解析和验证内存数据
    local mem_total=$(echo "$memory_raw" | sed -n 's/.*"total":\([^,}]*\).*/\1/p')
    local mem_used=$(echo "$memory_raw" | sed -n 's/.*"used":\([^,}]*\).*/\1/p')
    local mem_free=$(echo "$memory_raw" | sed -n 's/.*"free":\([^,}]*\).*/\1/p')
    local mem_usage_percent=$(echo "$memory_raw" | sed -n 's/.*"usage_percent":\([^,}]*\).*/\1/p')
    mem_total=$(sanitize_integer "$mem_total" "0")
    mem_used=$(sanitize_integer "$mem_used" "0")
    mem_free=$(sanitize_integer "$mem_free" "0")
    mem_usage_percent=$(sanitize_number "$mem_usage_percent" "0")

    # 解析和验证磁盘数据
    local disk_total=$(echo "$disk_raw" | sed -n 's/.*"total":\([^,}]*\).*/\1/p')
    local disk_used=$(echo "$disk_raw" | sed -n 's/.*"used":\([^,}]*\).*/\1/p')
    local disk_free=$(echo "$disk_raw" | sed -n 's/.*"free":\([^,}]*\).*/\1/p')
    local disk_usage_percent=$(echo "$disk_raw" | sed -n 's/.*"usage_percent":\([^,}]*\).*/\1/p')
    disk_total=$(sanitize_number "$disk_total" "0")
    disk_used=$(sanitize_number "$disk_used" "0")
    disk_free=$(sanitize_number "$disk_free" "0")
    disk_usage_percent=$(sanitize_integer "$disk_usage_percent" "0")

    # 解析和验证网络数据
    local net_upload_speed=$(echo "$network_raw" | sed -n 's/.*"upload_speed":\([^,}]*\).*/\1/p')
    local net_download_speed=$(echo "$network_raw" | sed -n 's/.*"download_speed":\([^,}]*\).*/\1/p')
    local net_total_upload=$(echo "$network_raw" | sed -n 's/.*"total_upload":\([^,}]*\).*/\1/p')
    local net_total_download=$(echo "$network_raw" | sed -n 's/.*"total_download":\([^,}]*\).*/\1/p')
    net_upload_speed=$(sanitize_integer "$net_upload_speed" "0")
    net_download_speed=$(sanitize_integer "$net_download_speed" "0")
    net_total_upload=$(sanitize_integer "$net_total_upload" "0")
    net_total_download=$(sanitize_integer "$net_total_download" "0")

    # 验证运行时间
    local uptime=$(sanitize_integer "$uptime_raw" "0")

    # 构建清理后的JSON数据
    local cpu_json="{\"usage_percent\":$cpu_usage,\"load_avg\":[$cpu_load]}"
    local memory_json="{\"total\":$mem_total,\"used\":$mem_used,\"free\":$mem_free,\"usage_percent\":$mem_usage_percent}"
    local disk_json="{\"total\":$disk_total,\"used\":$disk_used,\"free\":$disk_free,\"usage_percent\":$disk_usage_percent}"
    local network_json="{\"upload_speed\":$net_upload_speed,\"download_speed\":$net_download_speed,\"total_upload\":$net_total_upload,\"total_download\":$net_total_download}"

    local data="{\"timestamp\":$timestamp,\"cpu\":$cpu_json,\"memory\":$memory_json,\"disk\":$disk_json,\"network\":$network_json,\"uptime\":$uptime}"

    # 调试：记录发送的JSON数据和原始数据
    log "原始CPU数据: $cpu_raw"
    log "原始内存数据: $memory_raw"
    log "原始磁盘数据: $disk_raw"
    log "原始网络数据: $network_raw"
    log "原始运行时间: $uptime_raw"
    log "发送的JSON数据: $data"
    log "正在上报数据到 $WORKER_URL/api/report/$SERVER_ID"

    local response=$(curl -s -w "%{http_code}" -X POST "$WORKER_URL/api/report/$SERVER_ID" \
        -H "Content-Type: application/json" \
        -H "X-API-Key: $API_KEY" \
        -d "$data" 2>/dev/null || echo "000")

    local http_code="${response: -3}"
    local response_body="${response%???}"

    if [[ "$http_code" == "200" ]]; then
        log "数据上报成功"
        return 0
    else
        log "数据上报失败 (HTTP $http_code): $response_body"
        return 1
    fi
}

# 创建监控服务脚本
create_service_script() {
    # 获取当前脚本的绝对路径
    local main_script_path=$(realpath "$0")

    cat > "$SERVICE_FILE" << EOF
#!/bin/bash

# 监控服务脚本
SCRIPT_DIR="$HOME/.vps-monitor"
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
        # 临时文件包含所需的函数
        local temp_functions="/tmp/vps_monitor_functions_\$\$.sh"

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

# 上报监控数据
report_metrics() {
    local timestamp=\$(date +%s)
    local cpu_raw=\$(get_cpu_usage)
    local memory_raw=\$(get_memory_usage)
    local disk_raw=\$(get_disk_usage)
    local network_raw=\$(get_network_usage)
    local uptime_raw=\$(get_uptime)

    # 解析和验证CPU数据
    local cpu_usage=\$(echo "\$cpu_raw" | sed -n 's/.*"usage_percent":\\([^,}]*\\).*/\\1/p')
    local cpu_load_raw=\$(echo "\$cpu_raw" | sed -n 's/.*"load_avg":\\[\\([^\\]]*\\)\\].*/\\1/p')
    cpu_usage=\$(sanitize_number "\$cpu_usage" "0")

    # 清理CPU负载数组
    local cpu_load=""
    if [[ -n "\$cpu_load_raw" ]]; then
        local load1=\$(echo "\$cpu_load_raw" | cut -d',' -f1)
        local load5=\$(echo "\$cpu_load_raw" | cut -d',' -f2)
        local load15=\$(echo "\$cpu_load_raw" | cut -d',' -f3)
        load1=\$(sanitize_number "\$load1" "0")
        load5=\$(sanitize_number "\$load5" "0")
        load15=\$(sanitize_number "\$load15" "0")
        cpu_load="\$load1,\$load5,\$load15"
    else
        cpu_load="0,0,0"
    fi

    # 解析和验证内存数据
    local mem_total=\$(echo "\$memory_raw" | sed -n 's/.*"total":\\([^,}]*\\).*/\\1/p')
    local mem_used=\$(echo "\$memory_raw" | sed -n 's/.*"used":\\([^,}]*\\).*/\\1/p')
    local mem_free=\$(echo "\$memory_raw" | sed -n 's/.*"free":\\([^,}]*\\).*/\\1/p')
    local mem_usage_percent=\$(echo "\$memory_raw" | sed -n 's/.*"usage_percent":\\([^,}]*\\).*/\\1/p')
    mem_total=\$(sanitize_integer "\$mem_total" "0")
    mem_used=\$(sanitize_integer "\$mem_used" "0")
    mem_free=\$(sanitize_integer "\$mem_free" "0")
    mem_usage_percent=\$(sanitize_number "\$mem_usage_percent" "0")

    # 解析和验证磁盘数据
    local disk_total=\$(echo "\$disk_raw" | sed -n 's/.*"total":\\([^,}]*\\).*/\\1/p')
    local disk_used=\$(echo "\$disk_raw" | sed -n 's/.*"used":\\([^,}]*\\).*/\\1/p')
    local disk_free=\$(echo "\$disk_raw" | sed -n 's/.*"free":\\([^,}]*\\).*/\\1/p')
    local disk_usage_percent=\$(echo "\$disk_raw" | sed -n 's/.*"usage_percent":\\([^,}]*\\).*/\\1/p')
    disk_total=\$(sanitize_number "\$disk_total" "0")
    disk_used=\$(sanitize_number "\$disk_used" "0")
    disk_free=\$(sanitize_number "\$disk_free" "0")
    disk_usage_percent=\$(sanitize_integer "\$disk_usage_percent" "0")

    # 解析和验证网络数据
    local net_upload_speed=\$(echo "\$network_raw" | sed -n 's/.*"upload_speed":\\([^,}]*\\).*/\\1/p')
    local net_download_speed=\$(echo "\$network_raw" | sed -n 's/.*"download_speed":\\([^,}]*\\).*/\\1/p')
    local net_total_upload=\$(echo "\$network_raw" | sed -n 's/.*"total_upload":\\([^,}]*\\).*/\\1/p')
    local net_total_download=\$(echo "\$network_raw" | sed -n 's/.*"total_download":\\([^,}]*\\).*/\\1/p')
    net_upload_speed=\$(sanitize_integer "\$net_upload_speed" "0")
    net_download_speed=\$(sanitize_integer "\$net_download_speed" "0")
    net_total_upload=\$(sanitize_integer "\$net_total_upload" "0")
    net_total_download=\$(sanitize_integer "\$net_total_download" "0")

    # 验证运行时间
    local uptime=\$(sanitize_integer "\$uptime_raw" "0")

    # 构建清理后的JSON数据
    local cpu_json="{\\"usage_percent\\":\$cpu_usage,\\"load_avg\\":[\$cpu_load]}"
    local memory_json="{\\"total\\":\$mem_total,\\"used\\":\$mem_used,\\"free\\":\$mem_free,\\"usage_percent\\":\$mem_usage_percent}"
    local disk_json="{\\"total\\":\$disk_total,\\"used\\":\$disk_used,\\"free\\":\$disk_free,\\"usage_percent\\":\$disk_usage_percent}"
    local network_json="{\\"upload_speed\\":\$net_upload_speed,\\"download_speed\\":\$net_download_speed,\\"total_upload\\":\$net_total_upload,\\"total_download\\":\$net_total_download}"

    local data="{\\"timestamp\\":\$timestamp,\\"cpu\\":\$cpu_json,\\"memory\\":\$memory_json,\\"disk\\":\$disk_json,\\"network\\":\$network_json,\\"uptime\\":\$uptime}"

    log "正在上报数据..."

    local response=\$(curl -s -w "%{http_code}" -X POST "\$WORKER_URL/api/report/\$SERVER_ID" \\
        -H "Content-Type: application/json" \\
        -H "X-API-Key: \$API_KEY" \\
        -d "\$data" 2>/dev/null || echo "000")

    local http_code="\${response: -3}"
    local response_body="\${response%???}"

    if [[ "\$http_code" == "200" ]]; then
        log "数据上报成功"
        return 0
    else
        log "数据上报失败 (HTTP \$http_code): \$response_body"
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

    cat > "$SYSTEMD_SERVICE_FILE" << EOF
[Unit]
Description=VPS Monitor Service
After=network.target

[Service]
Type=simple
ExecStart=$SERVICE_FILE
Restart=always
RestartSec=10
User=$USER
WorkingDirectory=$SCRIPT_DIR

[Install]
WantedBy=default.target
EOF

    # 重新加载systemd配置
    systemctl --user daemon-reload
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
        if systemctl --user start vps-monitor.service; then
            systemctl --user enable vps-monitor.service
            print_message "$GREEN" "监控服务已启动 (systemd)"
            return 0
        else
            print_message "$YELLOW" "systemd启动失败，尝试传统方式"
        fi
    fi

    # 传统方式启动
    print_message "$BLUE" "使用传统方式启动服务..."
    nohup "$SERVICE_FILE" > /dev/null 2>&1 &
    local pid=$!
    echo "$pid" > "$PID_FILE"

    # 等待一下检查是否启动成功
    sleep 2
    if kill -0 "$pid" 2>/dev/null; then
        print_message "$GREEN" "监控服务已启动 (传统方式, PID: $pid)"
        return 0
    else
        print_message "$RED" "监控服务启动失败"
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
        if systemctl --user is-active vps-monitor.service >/dev/null 2>&1; then
            systemctl --user stop vps-monitor.service
            systemctl --user disable vps-monitor.service
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
        if systemctl --user is-active vps-monitor.service >/dev/null 2>&1; then
            print_message "$GREEN" "✓ systemd服务运行中"
            systemctl --user status vps-monitor.service --no-pager -l
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

# 调试网络监控
debug_network() {
    print_message "$BLUE" "调试网络监控功能..."
    echo

    # 确保OS变量已设置
    if [[ -z "$OS" ]]; then
        OS=$(uname -s)
        export OS
    fi

    print_message "$CYAN" "系统类型: $OS"
    echo

    # 检查网络接口
    print_message "$CYAN" "1. 检查网络接口:"
    if [[ "$OS" == "FreeBSD" ]]; then
        echo "FreeBSD系统 - 使用 route 命令:"
        if command_exists route; then
            route -n get default 2>/dev/null || echo "  无默认路由"
            local interface=$(route -n get default 2>/dev/null | grep 'interface:' | awk '{print $2}')
            if [[ -n "$interface" ]]; then
                echo "  默认接口: $interface"
            fi
        fi

        echo "可用网络接口:"
        if command_exists ifconfig; then
            ifconfig -l 2>/dev/null || echo "  无法获取接口列表"
        fi
    else
        # Linux系统
        if command_exists ip; then
            echo "使用 ip 命令:"
            ip route show default 2>/dev/null || echo "  无默认路由"
            local interface=$(ip route show default 2>/dev/null | awk '/default/ {print $5}' | head -1)
            if [[ -n "$interface" ]]; then
                echo "  默认接口: $interface"
            fi
        elif command_exists route; then
            echo "使用 route 命令:"
            route -n 2>/dev/null | grep '^0.0.0.0' || echo "  无默认路由"
            local interface=$(route -n 2>/dev/null | awk '/^0.0.0.0/ {print $8}' | head -1)
            if [[ -n "$interface" ]]; then
                echo "  默认接口: $interface"
            fi
        fi
    fi

    # 检查网络统计文件/命令
    echo
    if [[ "$OS" == "FreeBSD" ]]; then
        print_message "$CYAN" "2. 检查 netstat -i -b:"
        if command_exists netstat; then
            echo "netstat -i -b 输出:"
            netstat -i -b 2>/dev/null | head -5
            echo
            echo "活跃接口 (有流量的接口，仅显示Link层统计):"
            netstat -i -b | awk 'NR>1 && $1 !~ /^lo/ && $3 ~ /<Link#/ && ($8 > 0 || $11 > 0) {
                printf "  %s: RX=%s bytes, TX=%s bytes\n", $1, $8, $11
            }'
        else
            echo "  netstat 命令不可用"
        fi
    else
        print_message "$CYAN" "2. 检查 /proc/net/dev:"
        if [[ -f "/proc/net/dev" ]]; then
            echo "前5行内容:"
            head -5 /proc/net/dev
            echo
            echo "活跃接口 (有流量的接口):"
            awk '/^ *[^:]*:/ {
                gsub(/:/, "", $1)
                if ($1 != "lo" && ($2 > 0 || $10 > 0)) {
                    printf "  %s: RX=%s bytes, TX=%s bytes\n", $1, $2, $10
                }
            }' /proc/net/dev
        else
            echo "  /proc/net/dev 不存在"
        fi
    fi

    # 测试网络监控函数
    echo
    print_message "$CYAN" "3. 测试网络监控函数:"
    local network_data=$(get_network_usage)
    echo "  返回数据: $network_data"

    # 解析并显示
    if command_exists jq; then
        echo "  解析结果:"
        echo "$network_data" | jq .
    else
        echo "  (安装 jq 可以更好地显示JSON数据)"
    fi

    # 检查ifstat
    echo
    print_message "$CYAN" "4. 检查 ifstat:"
    if command_exists ifstat; then
        echo "  ✓ ifstat 已安装"
        local interface=$(ip route show default 2>/dev/null | awk '/default/ {print $5}' | head -1)
        if [[ -n "$interface" ]]; then
            echo "  测试 ifstat -i $interface 1 1:"
            timeout 5 ifstat -i "$interface" 1 1 2>/dev/null || echo "    ifstat 执行失败"
        fi
    else
        echo "  ✗ ifstat 未安装"
        echo "  安装命令:"
        if command_exists apt-get; then
            echo "    sudo apt-get install ifstat"
        elif command_exists yum; then
            echo "    sudo yum install ifstat"
        elif command_exists dnf; then
            echo "    sudo dnf install ifstat"
        fi
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

    # 上报间隔
    echo -n "请输入上报间隔(秒)"
    if [[ -n "$INTERVAL" ]]; then
        echo -n " (当前: $INTERVAL)"
    fi
    echo -n ": "
    read -r input_interval
    if [[ -n "$input_interval" && "$input_interval" =~ ^[0-9]+$ ]]; then
        INTERVAL="$input_interval"
    fi

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
    echo "  debug       调试网络监控"
    echo "  menu        显示交互菜单"
    echo "  help        显示此帮助信息"
    echo
    echo "一键安装参数:"
    echo "  -i, --install           一键安装模式"
    echo "  -s, --server-id ID      服务器ID"
    echo "  -k, --api-key KEY       API密钥"
    echo "  -u, --worker-url URL    Worker地址"
    echo "  --interval SECONDS      上报间隔（秒，默认60）"
    echo
    echo "示例:"
    echo "  $0 install              # 交互式安装"
    echo "  $0 status               # 查看服务状态"
    echo "  $0 logs                 # 查看日志"
    echo
    echo "一键安装示例:"
    echo "  $0 -i -s server123 -k abc123 -u https://worker.example.com --interval 60"
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
        echo "9. 调试网络监控"
        echo "10. 彻底卸载服务"
        echo "0. 退出"
        echo
        print_message "$YELLOW" "请选择操作 (0-10): "
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
                debug_network
                echo
                print_message "$BLUE" "按任意键继续..."
                read -r
                ;;
            10)
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
    local interval="${4:-60}"

    print_message "$BLUE" "开始一键安装VPS监控服务..."
    echo

    # 验证必需参数
    if [[ -z "$server_id" || -z "$api_key" || -z "$worker_url" ]]; then
        print_message "$RED" "错误: 缺少必需参数"
        echo "必需参数: -s <服务器ID> -k <API密钥> -u <Worker地址>"
        echo "使用 '$0 --help' 查看详细帮助"
        return 1
    fi

    # 验证间隔参数
    if ! [[ "$interval" =~ ^[0-9]+$ ]] || [[ "$interval" -lt 10 ]]; then
        print_message "$YELLOW" "警告: 无效的上报间隔，使用默认值60秒"
        interval=60
    fi

    print_message "$CYAN" "安装参数:"
    echo "  服务器ID: $server_id"
    echo "  API密钥: ${api_key:0:8}..."
    echo "  Worker地址: $worker_url"
    echo "  上报间隔: ${interval}秒"
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
        debug)
            debug_network
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
