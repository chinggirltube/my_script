#!/bin/bash

GREEN="\033[32m"
RED="\033[31m"
YELLOW="\033[0;33m"
NC="\033[0m"
GREEN_ground="\033[42;37m" 
RED_ground="\033[41;37m"   
Info="${GREEN}[信息]${NC}"
Error="${RED}[错误]${NC}"
Tip="${YELLOW}[提示]${NC}"

cop_info(){
clear
echo -e "${GREEN}#######################################################
#      ${RED}Debian DDNS 一键脚本 ${GREEN}       #
#               作者: ${YELLOW}LaoWangI           ${GREEN}#
#             https://github.com/chinggirltube/                  ${GREEN}#
#  ${YELLOW}优化: 缓存ZoneID, 重构更新逻辑, 加固文件权限${GREEN} #
#######################################################${NC}"
echo -e "${Info}"
echo
}

if ! grep -qiE "debian|ubuntu" /etc/os-release; then
    echo -e "${Error}本脚本仅支持 Debian 或 Ubuntu 系统。"
    exit 1
fi

check_root(){
    if [[ $(whoami) != "root" ]]; then
        echo -e "${Error}请以root身份执行该脚本！"
        exit 1
    fi
}

check_curl() {
    if ! command -v curl &>/dev/null || ! command -v jq &>/dev/null; then
        echo -e "${YELLOW}未检测到 curl 或 jq，正在安装...${NC}"
        apt-get update && apt-get install -y curl jq
        if [ $? -ne 0 ]; then
            echo -e "${RED}安装 curl/jq 失败，请手动安装后重试。${NC}"
            exit 1
        fi
    fi
}

install_ddns(){
    if [ -d "/etc/DDNS" ]; then
        echo -e "${Tip}检测到已存在的DDNS目录，将备份为 /etc/DDNS.bak_$(date +%s)"
        mv /etc/DDNS "/etc/DDNS.bak_$(date +%s)" 2>/dev/null
    fi

    mkdir -p /etc/DDNS
    
    cp "$0" /usr/bin/ddns && chmod +x /usr/bin/ddns

    cat <<'EOF' > /etc/DDNS/.config
Domain="your_domain.com"
Domainv6="your_domainv6.com" 
Email="your_email@gmail.com"
Api_key="your_api_key"

Telegram_Bot_Token=""
Telegram_Chat_ID=""
EOF
    chmod 600 /etc/DDNS/.config 

    touch /etc/DDNS/.old_ipv4 && chmod 600 /etc/DDNS/.old_ipv4
    touch /etc/DDNS/.old_ipv6 && chmod 600 /etc/DDNS/.old_ipv6

    cat <<'EOF' > /etc/DDNS/DDNS
#!/bin/bash

WORK_DIR="/etc/DDNS"

LOG_FILE="/var/log/ddns.log"

declare -A ZONE_ID_CACHE

log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" >> "$LOG_FILE"
}

send_telegram_notification(){
    local message="$1"
    if [[ -n "$Telegram_Bot_Token" && -n "$Telegram_Chat_ID" ]]; then
        log "正在发送Telegram通知..."
        curl -s --connect-timeout 10 -X POST "https://api.telegram.org/bot$Telegram_Bot_Token/sendMessage" \
             -d chat_id="$Telegram_Chat_ID" -d text="$message" >> "$LOG_FILE" 2>&1
    else
        log "Telegram通知未配置或配置不完整，跳过发送。"
    fi
}

get_root_domain() {
    echo "$1" | awk -F. '{print $(NF-1)"."$NF}'
}

get_zone_id() {
    local full_domain=$1
    local root_domain
    root_domain=$(get_root_domain "$full_domain")

    if [[ -n "${ZONE_ID_CACHE[$root_domain]}" ]]; then
        log "从缓存命中 Zone ID for $root_domain: ${ZONE_ID_CACHE[$root_domain]}"
        echo "${ZONE_ID_CACHE[$root_domain]}"
        return
    fi

    log "通过API获取 Zone ID for $root_domain..."
    local zone_id_val
    ZONE_ID_RESPONSE=$(curl -s -X GET "https://api.cloudflare.com/client/v4/zones?name=$root_domain" \
         -H "X-Auth-Email: $Email" \
         -H "X-Auth-Key: $Api_key" \
         -H "Content-Type: application/json")
    zone_id_val=$(echo "$ZONE_ID_RESPONSE" | jq -r '.result[] | select(.name=="'"$root_domain"'") | .id' 2>/dev/null)

    if [ -z "$zone_id_val" ]; then
        log "错误: 无法获取 Zone ID for '$root_domain'. 检查邮箱、API Key或根域名。API响应: $ZONE_ID_RESPONSE"
        send_telegram_notification "DDNS 错误: 无法获取 ${root_domain} 的 Cloudflare Zone ID。"
        echo ""
    else
        log "获取成功! Zone ID for $root_domain: $zone_id_val. 已缓存。"
        ZONE_ID_CACHE["$root_domain"]="$zone_id_val"
        echo "$zone_id_val"
    fi
}

get_dns_record_id() {
    local zone_id=$1
    local record_type=$2
    local domain_name=$3
    
    log "尝试获取 DNS Record ID for $domain_name (Type $record_type)..."
    DNS_ID_RESPONSE=$(curl -s -X GET "https://api.cloudflare.com/client/v4/zones/$zone_id/dns_records?type=$record_type&name=$domain_name" \
         -H "X-Auth-Email: $Email" \
         -H "X-Auth-Key: $Api_key" \
         -H "Content-Type: application/json")
    local dns_id_val
    dns_id_val=$(echo "$DNS_ID_RESPONSE" | jq -r '.result[0].id' 2>/dev/null)

    if [ -z "$dns_id_val" ]; then
        log "警告: 无法获取 '$domain_name' 的 $record_type 记录 ID. 请确保该记录已存在。API响应: $DNS_ID_RESPONSE"
        echo ""
    else
        log "DNS Record ID for $domain_name: $dns_id_val"
        echo "$dns_id_val"
    fi
}

update_dns_record() {
    local record_type=$1
    local domain=$2
    local public_ip=$3
    local old_ip=$4
    local old_ip_file=$5
    
    if [[ "$public_ip" == "$old_ip" ]]; then
        log "$record_type 地址 ($public_ip) 未变化。"
        return 0
    fi

    log "检测到 $record_type 地址变化: 旧[$old_ip] -> 新[$public_ip]"

    local zone_id
    zone_id=$(get_zone_id "$domain")
    if [ -z "$zone_id" ]; then
        log "错误: 因无法获取Zone ID，跳过 $domain 的更新。"
        return 1
    fi
    
    local dns_id
    dns_id=$(get_dns_record_id "$zone_id" "$record_type" "$domain")
    if [ -z "$dns_id" ]; then
        log "错误: 因无法获取DNS Record ID，跳过 $domain 的更新。"
        send_telegram_notification "DDNS 错误: 更新 ${domain} ($record_type) 失败，无法获取 DNS Record ID。"
        return 1
    fi

    log "正在更新 $domain ($record_type) -> $public_ip..."
    response=$(curl -s -w "%{http_code}" -X PUT "https://api.cloudflare.com/client/v4/zones/$zone_id/dns_records/$dns_id" \
         -H "X-Auth-Email: $Email" \
         -H "X-Auth-Key: $Api_key" \
         -H "Content-Type: application/json" \
         --data "{\"type\":\"$record_type\",\"name\":\"$domain\",\"content\":\"$public_ip\",\"ttl\":60,\"proxied\":false}")
    
    http_code=${response: -3}
    body=${response::-3}

    if [ "$http_code" -eq 200 ] && [[ "$body" == *"\"success\":true"* ]]; then
        log "成功: $domain 的 $record_type 记录已更新为 $public_ip"
        echo "$public_ip" > "$old_ip_file"
        echo "${domain} 的 ${record_type} 地址已更新为 ${public_ip}。旧IP为 ${old_ip}。"
        return 0
    else
        log "失败: 更新 $domain 失败。HTTP Code: $http_code, Response: $body"
        send_telegram_notification "DDNS 错误: 更新 ${domain} ($record_type) 失败. HTTP Code: ${http_code}."
        return 1
    fi
}

log "====== DDNS 任务开始 ======"
cd "$WORK_DIR" || { log "错误: 无法进入DDNS工作目录 $WORK_DIR"; exit 1; }

source .config

ipv4Regex="^([0-9]{1,3}\.){3}[0-9]{1,3}$"
ipv6Regex="^([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])$"

log "正在从多个源获取公网IP地址..."
raw_ipv4=$(curl -s4 --max-time 10 https://api.ipify.org || curl -s4 --max-time 10 https://ip.sb || curl -s4 --max-time 10 https://ipv4.icanhazip.com)
raw_ipv6=$(curl -s6 --max-time 10 https://api6.ipify.org || curl -s6 --max-time 10 https://ip.sb || curl -s6 --max-time 10 https://ipv6.icanhazip.com)

Public_IPv4=""
if [[ -n "$raw_ipv4" && "$raw_ipv4" =~ $ipv4Regex ]]; then
    Public_IPv4="$raw_ipv4"
    log "成功获取并验证公网 IPv4: $Public_IPv4"
else
    log "警告: 获取到的IPv4内容不是有效地址: '$raw_ipv4'。将忽略IPv4更新。"
fi

Public_IPv6=""
if [[ -n "$raw_ipv6" && "$raw_ipv6" =~ $ipv6Regex ]]; then
    Public_IPv6="$raw_ipv6"
    log "成功获取并验证公网 IPv6: $Public_IPv6"
else
    log "警告: 获取到的IPv6内容不是有效地址: '$raw_ipv6'。将忽略IPv6更新。"
fi

Old_Public_IPv4=$(cat "$WORK_DIR/.old_ipv4" 2>/dev/null)
Old_Public_IPv6=$(cat "$WORK_DIR/.old_ipv6" 2>/dev/null)
log "旧IPv4: [$Old_Public_IPv4], 旧IPv6: [$Old_Public_IPv6]"

notification_message=""
update_result=""

if [[ -n "$Domain" && "$Domain" != "your_domain.com" && -n "$Public_IPv4" ]]; then
    update_result=$(update_dns_record "A" "$Domain" "$Public_IPv4" "$Old_Public_IPv4" "$WORK_DIR/.old_ipv4")
    if [[ $? -eq 0 && -n "$update_result" ]]; then
        notification_message+="$update_result "
    fi
else
    log "跳过 IPv4 更新：未配置域名或未获取到有效的公网IP。"
fi

if [[ -n "$Domainv6" && "$Domainv6" != "your_domainv6.com" && -n "$Public_IPv6" ]]; then
    update_result=$(update_dns_record "AAAA" "$Domainv6" "$Public_IPv6" "$Old_Public_IPv6" "$WORK_DIR/.old_ipv6")
    if [[ $? -eq 0 && -n "$update_result" ]]; then
        notification_message+="$update_result "
    fi
else
    log "跳过 IPv6 更新：未配置域名或未获取到有效的公网IP。"
fi

if [ -n "$notification_message" ]; then
    log "IP发生变化，准备发送最终通知。"
    send_telegram_notification "$notification_message"
else
    log "所有IP均未变化或无需更新，不发送通知。"
fi

log "====== DDNS 任务结束 ======"
EOF
    
    chmod 700 /etc/DDNS/DDNS

    touch /var/log/ddns.log && chmod 644 /var/log/ddns.log
    
    echo -e "${Info}DDNS 文件安装完成！"
    echo -e "${Tip}核心逻辑脚本位于: ${YELLOW}/etc/DDNS/DDNS${NC}"
    echo -e "${Tip}配置文件位于: ${YELLOW}/etc/DDNS/.config (权限600)${NC}"
    echo -e "${Tip}IP状态文件权限已设置为 600。"
    echo -e "${Tip}日志文件位于: ${YELLOW}/var/log/ddns.log${NC}"
    echo
}


check_ddns_status(){
    if systemctl is-active --quiet ddns.timer; then
        ddns_status="running"
    else
        ddns_status="dead"
    fi
}

test_telegram_notification(){
    echo -e "${Tip}正在测试 Telegram 通知...${NC}"
    source /etc/DDNS/.config

    if [[ -z "$Telegram_Bot_Token" || -z "$Telegram_Chat_ID" ]]; then
        echo -e "${Error}Telegram Bot Token 或 Chat ID 未配置。请先通过选项 ${GREEN}5${NC} 进行配置。${NC}"
        return 1
    fi
    
    current_ipv4=$(curl -s4 --max-time 5 https://api.ipify.org || echo "N/A")
    local test_message="DDNS (最终修正版) 测试通知。服务器IP: ${current_ipv4}。如果能收到此消息，说明Telegram通知功能正常。"
    
    echo -e "${Info}尝试发送测试消息...详情请查看 /var/log/ddns.log"
    
    (
    Telegram_Bot_Token="$Telegram_Bot_Token"
    Telegram_Chat_ID="$Telegram_Chat_ID"
    LOG_FILE="/var/log/ddns.log"
    source /etc/DDNS/DDNS
    send_telegram_notification "$test_message"
    )

    echo -e "${Info}测试消息已发送（或尝试发送）。请查看 Telegram 和 ${YELLOW}/var/log/ddns.log${NC} 确认结果。"
}

go_ahead(){
    echo -e "${Tip}请选择一个操作：
  ${GREEN}1${NC}：启动 / 重启 DDNS
  ${GREEN}2${NC}：停止 DDNS
  ${GREEN}3${NC}：修改要解析的域名
  ${GREEN}4${NC}：修改 Cloudflare API
  ${GREEN}5${NC}：配置 Telegram 通知
  ${GREEN}6${NC}：${RED}彻底卸载 DDNS${NC}
  ${GREEN}7${NC}：查看 DDNS 实时日志
  ${GREEN}8${NC}：测试 Telegram 通知
  ${GREEN}9${NC}：立即手动执行一次DDNS检查
  ${GREEN}0${NC}：退出脚本"
    echo
    read -p "请输入选项 [0-9]: " option
    case "$option" in
        0) exit 0 ;;
        1) restart_ddns; main ;;
        2) stop_ddns; main ;;
        3) set_domain; restart_ddns; sleep 2; main ;;
        4) set_cloudflare_api; restart_ddns; sleep 2; main ;;
        5) set_telegram_settings; restart_ddns; sleep 2; main ;;
        6) uninstall_ddns ;;
        7) echo -e "${Info}正在显示实时日志... 按 ${RED}Ctrl+C${NC} 退出。"; tail -f /var/log/ddns.log; main ;;
        8) test_telegram_notification; sleep 2; main ;;
        9) echo -e "${Info}正在手动触发一次DDNS检查..."; systemctl start ddns.service; echo -e "${Info}已触发，请通过日志查看结果。"; sleep 2; main ;;
        *) echo -e "${Error}无效的输入！"; sleep 2; main ;;
    esac
}

uninstall_ddns(){
    read -p "你确定要彻底卸载 DDNS 吗? 这会删除所有配置和脚本。[y/N]: " confirm
    if [[ ! "${confirm,,}" =~ ^y$ ]]; then
        echo -e "${Info}操作已取消。"
        main
        return
    fi
    echo -e "${Tip}正在停止并禁用 systemd 服务..."
    systemctl disable --now ddns.service ddns.timer >/dev/null 2>&1
    echo -e "${Tip}正在删除相关文件..."
    rm -f /etc/systemd/system/ddns.service /etc/systemd/system/ddns.timer
    rm -rf /etc/DDNS /usr/bin/ddns
    rm -f /var/log/ddns.log
    systemctl daemon-reload
    echo -e "${Info}DDNS 已成功卸载！"
    echo
}

set_cloudflare_api(){
    echo -e "${Tip}开始配置 Cloudflare API..." && echo
    read -p "请输入您的 Cloudflare 邮箱: " email
    read -p "请输入您的 Cloudflare Global API Key: " api_key
    
    if [ -z "$email" ] || [ -z "$api_key" ]; then
        echo -e "${Error}邮箱和 API Key 不能为空！"
        return 1
    fi
    
    sed -i "s/^Email=.*/Email=\"$email\"/" /etc/DDNS/.config
    sed -i "s/^Api_key=.*/Api_key=\"$api_key\"/" /etc/DDNS/.config
    
    echo -e "${Info}Cloudflare API 设置已更新！"
}

set_domain(){
    echo && echo -e "${Tip}开始配置要解析的域名..."
    
    echo -e "${Tip}请输入要解析的 IPv4 域名 (如: v4.yourdomain.com, 回车跳过):"
    read -p "IPv4 域名: " domain_v4
    sed -i "s/^Domain=.*/Domain=\"$domain_v4\"/" /etc/DDNS/.config
    
    echo -e "${Tip}请输入要解析的 IPv6 域名 (如: v6.yourdomain.com, 回车跳过):"
    read -p "IPv6 域名: " domain_v6
    sed -i "s/^Domainv6=.*/Domainv6=\"$domain_v6\"/" /etc/DDNS/.config
    
    echo -e "${Info}域名设置已更新！"
}

set_telegram_settings(){
    echo && echo -e "${Tip}开始配置 Telegram 通知 (全部留空则禁用)..."
    read -p "请输入您的 Telegram Bot Token: " token
    read -p "请输入您的 Telegram Chat ID: " chat_id
    
    sed -i "s/^Telegram_Bot_Token=.*/Telegram_Bot_Token=\"$token\"/" /etc/DDNS/.config
    sed -i "s/^Telegram_Chat_ID=.*/Telegram_Chat_ID=\"$chat_id\"/" /etc/DDNS/.config
    
    echo -e "${Info}Telegram 设置已更新！"
}

run_ddns(){
    if [ ! -f "/etc/systemd/system/ddns.service" ]; then
        cat > /etc/systemd/system/ddns.service <<EOF
[Unit]
Description=Dynamic DNS Update Service (Cloudflare)
After=network.target nss-lookup.target

[Service]
Type=simple
ExecStart=/bin/bash /etc/DDNS/DDNS
WorkingDirectory=/etc/DDNS

[Install]
WantedBy=multi-user.target
EOF
    fi

    if [ ! -f "/etc/systemd/system/ddns.timer" ]; then
        cat > /etc/systemd/system/ddns.timer <<EOF
[Unit]
Description=Run DDNS job every 5 minutes

[Timer]
OnBootSec=2min
OnUnitActiveSec=5min
Unit=ddns.service

[Install]
WantedBy=timers.target
EOF
    fi

    systemctl daemon-reload
    restart_ddns
}

restart_ddns(){
    echo -e "${Info}正在启动/重启 DDNS 定时任务..."
    systemctl start ddns.service
    systemctl enable --now ddns.timer >/dev/null 2>&1
    echo -e "${Info}DDNS 服务已启动。将每5分钟检查一次IP变更。"
}

stop_ddns(){
    echo -e "${Info}正在停止 DDNS 定时任务..."
    systemctl disable --now ddns.timer >/dev/null 2>&1
    systemctl stop ddns.service >/dev/null 2>&1
    echo -e "${Info}DDNS 已停止。"
}

main(){
    if [[ -z "$IS_RECURSIVE" ]]; then
        cop_info
    fi
    
    if [ ! -f "/etc/DDNS/.config" ] || [ ! -f "/usr/bin/ddns" ]; then
        echo -e "${Tip}首次运行，开始安装流程..."
        install_ddns
        set_cloudflare_api
        set_domain
        set_telegram_settings
        run_ddns
        echo
        echo -e "${GREEN_ground} DDNS (最终修正版) 安装并配置成功！ ${NC}"
        echo -e "${Info}你可以随时再次运行此脚本或直接输入 ${GREEN}ddns${NC} 进行管理。"
        echo -e "${Info}重要：请通过选项 ${GREEN}7${NC} 查看日志以确认首次运行是否成功。"
        echo
    else
        check_ddns_status
        if [[ "$ddns_status" == "running" ]]; then
            echo -e "${Info}DDNS 状态: ${GREEN}已安装${NC} | ${GREEN}运行中${NC}"
        else
            echo -e "${Info}DDNS 状态: ${GREEN}已安装${NC} | ${RED}已停止${NC}"
        fi
        echo
    fi
    
    export IS_RECURSIVE=true
    go_ahead
}

check_root
check_curl
main
