#!/bin/bash
RULES_FILE="rules.config"
FAIL2BAN_LOCAL_CONFIG="/etc/fail2ban/jail.local"
FAIL2BAN_JAIL_DIR="/etc/fail2ban/jail.d/"
SSH_PORT=22
SSH_PROTO="tcp"

# Функции утилиты
pause() { 
    echo ""
    read -rp "Нажмите Enter для продолжения..." 
}

check_root() { 
    [[ $EUID -ne 0 ]] && echo "❌ Запустите скрипт от root" && exit 1 
}

validate_port() { 
    [[ "$1" =~ ^[0-9]+$ ]] && (( $1 >= 1 && $1 <= 65535 )) 
}

validate_protocol() { 
    [[ "$1" == "tcp" || "$1" == "udp" || "$1" == "both" ]] 
}

validate_direction() { 
    [[ "$1" == "IN" || "$1" == "OUT" || "$1" == "BOTH" ]] 
}

ufw_rule_exists() { 
    ufw status | grep -qw "$1/$2" 2>/dev/null 
}

config_rule_exists() { 
    grep -q ":$1:$2:$3$" "$RULES_FILE" 2>/dev/null 
}

# Функции Fail2ban
fail2ban_installed() { 
    command -v fail2ban-client >/dev/null 2>&1 
}

fail2ban_status() { 
    if fail2ban_installed; then
        echo "📊 Статус Fail2ban:"
        systemctl status fail2ban --no-pager | head -20
    else
        echo "❌ fail2ban не установлен"
    fi
}

get_fail2ban_jails() { 
    if fail2ban_installed; then
        fail2ban-client status 2>/dev/null | grep "Jail list" | sed 's/.*Jail list:\s*//' | tr ',' ' ' | tr -d ' '
    else
        echo ""
    fi
}

get_jail_port_proto() { 
    local jail=$1 
    local port proto
    
    if fail2ban_installed; then
        port=$(fail2ban-client get "$jail" port 2>/dev/null)
        proto=$(fail2ban-client get "$jail" protocol 2>/dev/null)
        [[ -z "$proto" ]] && proto="tcp"
        echo "$port:$proto"
    else
        echo ""
    fi
}

jail_exists() { 
    if ! fail2ban_installed; then
        return 1
    fi
    local jail_name="$1"
    fail2ban-client status "$jail_name" >/dev/null 2>&1
    return $?
}

# Создание дефолтных jails для HTTP и HTTPS
create_default_http_jails() {
    echo "🌐 Создание дефолтных jails для HTTP и HTTPS..."
    
    # Jail для HTTP (порт 80)
    if ! jail_exists "http"; then
        local http_config="$FAIL2BAN_JAIL_DIR/http.local"
        cat > "$http_config" << EOF
[http]
enabled = true
port = http,80
protocol = tcp
filter = http
logpath = /var/log/nginx/access.log
            /var/log/apache2/access.log
            /var/log/apache/access.log
maxretry = 5
bantime = 3600
findtime = 600
ignoreip = 127.0.0.1/8 ::1
action = ufw[name=UFW, port="\$(port)", protocol="\$(protocol)"]
EOF
        
        # Фильтр для HTTP
        local http_filter="/etc/fail2ban/filter.d/http.conf"
        cat > "$http_filter" << EOF
[Definition]
failregex = ^<HOST> -.*"(GET|POST|HEAD).*".*(404|403|500).*$
            ^.*<HOST>.*"GET.*wp-admin.*".*$
            ^.*<HOST>.*"POST.*wp-login.*".*$
            ^.*<HOST>.*".*(sql注入|XSS|扫描).*$
ignoreregex = 
EOF
        echo "✅ HTTP jail создан (порт 80)"
    fi
    
    # Jail для HTTPS (порт 443)
    if ! jail_exists "https"; then
        local https_config="$FAIL2BAN_JAIL_DIR/https.local"
        cat > "$https_config" << EOF
[https]
enabled = true
port = https,443
protocol = tcp
filter = https
logpath = /var/log/nginx/access.log
            /var/log/apache2/access.log
            /var/log/apache/access.log
maxretry = 5
bantime = 3600
findtime = 600
ignoreip = 127.0.0.1/8 ::1
action = ufw[name=UFW, port="\$(port)", protocol="\$(protocol)"]
EOF
        
        # Фильтр для HTTPS
        local https_filter="/etc/fail2ban/filter.d/https.conf"
        cat > "$https_filter" << EOF
[Definition]
failregex = ^<HOST> -.*"(GET|POST|HEAD).*".*(404|403|500).*$
            ^.*<HOST>.*"GET.*wp-admin.*".*$
            ^.*<HOST>.*"POST.*wp-login.*".*$
            ^.*<HOST>.*".*(恶意请求|攻击尝试).*$
ignoreregex = 
EOF
        echo "✅ HTTPS jail создан (порт 443)"
    fi
    
    # Перезагружаем fail2ban
    systemctl restart fail2ban 2>/dev/null || systemctl reload fail2ban 2>/dev/null
    echo "✅ Дефолтные jails для HTTP/HTTPS настроены"
}

# Инициализация файла правил с проверкой и созданием если нужно
populate_default_rules() {
    echo "📝 Создание файла правил с настройками по умолчанию..."
    cat > "$RULES_FILE" << EOF
# Файл конфигурации правил UFW
# Формат: Имя:Направление:Порт:Протокол
# Направление: IN, OUT, BOTH
# Протокол: tcp, udp, both

# Основные службы
SSH:IN:22:tcp
HTTP:IN:80:tcp
HTTPS:IN:443:tcp

# Дополнительные службы (раскомментируйте при необходимости)
#DNS:OUT:53:both
#NTP:OUT:123:udp
#SMTP:OUT:25:tcp
#MySQL:IN:3306:tcp
#PostgreSQL:IN:5432:tcp
EOF
    echo "✅ Файл $RULES_FILE создан с правилами по умолчанию"
}

init_rules_file() { 
    echo "🔍 Проверка файла правил..."
    if [[ ! -f "$RULES_FILE" ]]; then
        echo "📄 Файл $RULES_FILE не существует. Создаю..."
        populate_default_rules
    elif [[ ! -s "$RULES_FILE" ]]; then
        echo "📄 Файл $RULES_FILE пуст. Заполняю правилами по умолчанию..."
        populate_default_rules
    else
        echo "✅ Файл $RULES_FILE уже существует и содержит правила"
        # Проверяем есть ли основные правила
        if ! grep -q "SSH:IN:22:tcp" "$RULES_FILE"; then
            echo "⚠️ В файле нет основных правил. Добавляю..."
            echo "SSH:IN:22:tcp" >> "$RULES_FILE"
            echo "HTTP:IN:80:tcp" >> "$RULES_FILE"
            echo "HTTPS:IN:443:tcp" >> "$RULES_FILE"
        fi
    fi
}

# Работа с правилами UFW
apply_rule() {
    local dir=$1 port=$2 proto=$3
    [[ "$proto" == "both" ]] && { 
        apply_rule "$dir" "$port" tcp
        apply_rule "$dir" "$port" udp
        return
    }
    
    if ufw_rule_exists "$port" "$proto"; then
        echo "⚠️ $dir $port/$proto уже существует"
        return
    fi
    
    case "$dir" in
        IN) 
            ufw allow "$port/$proto" >/dev/null 2>&1
            echo "✅ Правило IN $port/$proto добавлено"
            ;;
        OUT) 
            ufw allow out "$port/$proto" >/dev/null 2>&1
            echo "✅ Правило OUT $port/$proto добавлено"
            ;;
        BOTH) 
            ufw allow "$port/$proto" >/dev/null 2>&1
            ufw allow out "$port/$proto" >/dev/null 2>&1
            echo "✅ Правило BOTH $port/$proto добавлено"
            ;;
    esac
}

delete_rule() {
    local dir=$1 port=$2 proto=$3
    
    if [[ "$port" == "$SSH_PORT" && "$proto" == "$SSH_PROTO" ]]; then
        echo "❌ Удаление SSH запрещено"
        return
    fi
    
    [[ "$proto" == "both" ]] && { 
        delete_rule "$dir" "$port" tcp
        delete_rule "$dir" "$port" udp
        return
    }
    
    case "$dir" in
        IN) 
            ufw delete allow "$port/$proto" >/dev/null 2>&1
            echo "✅ Правило IN $port/$proto удалено"
            ;;
        OUT) 
            ufw delete allow out "$port/$proto" >/dev/null 2>&1
            echo "✅ Правило OUT $port/$proto удалено"
            ;;
        BOTH) 
            ufw delete allow "$port/$proto" >/dev/null 2>&1
            ufw delete allow out "$port/$proto" >/dev/null 2>&1
            echo "✅ Правило BOTH $port/$proto удалено"
            ;;
    esac
}

# Функции Fail2ban
create_ufw_rule_from_jail() {
    if ! fail2ban_installed; then
        echo "❌ fail2ban не установлен"
        return
    fi
    
    local jail=$1 port proto
    IFS=":" read -r port proto <<< "$(get_jail_port_proto "$jail")"
    
    if [[ -z "$port" ]]; then
        echo "⚠️ Не удалось определить порт для $jail"
        return
    fi
    
    if ufw_rule_exists "$port" "$proto"; then
        echo "⚠️ UFW правило для $jail уже существует"
        return
    fi
    
    echo "➕ Добавление UFW правила для jail $jail ($port/$proto)"
    ufw allow "$port/$proto" >/dev/null 2>&1
    
    if ! config_rule_exists "IN" "$port" "$proto"; then
        echo "fail2ban-$jail:IN:$port:$proto" >> "$RULES_FILE"
    fi
}

fail2ban_autosync() { 
    if ! fail2ban_installed; then
        echo "❌ fail2ban не установлен"
        return
    fi
    
    local jails=$(get_fail2ban_jails)
    if [[ -z "$jails" ]]; then
        echo "⚠️ Нет активных jails"
        return
    fi
    
    for jail in $jails; do
        create_ufw_rule_from_jail "$jail"
    done
    echo "✅ Автосинхронизация завершена"
}

fail2ban_unban_ip() {
    if ! fail2ban_installed; then
        echo "❌ fail2ban не установлен"
        return
    fi
    
    read -rp "Введите IP для разблокировки: " ip
    [[ -z "$ip" ]] && { echo "❌ IP не указан"; return; }
    
    local jails=$(get_fail2ban_jails)
    if [[ -z "$jails" ]]; then
        echo "⚠️ Нет активных jails"
        return
    fi
    
    for jail in $jails; do
        if fail2ban-client set "$jail" unbanip "$ip" 2>/dev/null; then
            echo "✅ $ip разблокирован в $jail"
        else
            echo "⚠️ $ip не найден в $jail"
        fi
    done
}

# Создание нового jail
create_fail2ban_jail() {
    if ! fail2ban_installed; then
        echo "❌ fail2ban не установлен"
        echo "Установите fail2ban через пункт меню 10"
        pause
        return
    fi
    
    echo "➕ Создание нового Fail2ban Jail"
    echo ""
    
    while true; do
        read -rp "Введите имя jail (латинские буквы, цифры, дефисы): " jail_name
        [[ -z "$jail_name" ]] && { echo "❌ Имя не может быть пустым"; continue; }
        
        if jail_exists "$jail_name"; then
            echo "❌ Jail '$jail_name' уже существует"
            continue
        fi
        
        if [[ ! "$jail_name" =~ ^[a-zA-Z0-9_-]+$ ]]; then
            echo "❌ Некорректное имя. Используйте только латинские буквы, цифры, дефисы"
            continue
        fi
        break
    done
    
    read -rp "Порт для мониторинга (например: 22, 80,443 или all): " jail_port
    jail_port=${jail_port:-all}
    
    read -rp "Протокол (tcp/udp, по умолчанию: tcp): " jail_protocol
    jail_protocol=${jail_protocol:-tcp}
    
    read -rp "Время блокировки в секундах (по умолчанию: 600): " bantime
    bantime=${bantime:-600}
    
    read -rp "Максимальное количество попыток (по умолчанию: 3): " maxretry
    maxretry=${maxretry:-3}
    
    read -rp "Время поиска в секундах (по умолчанию: 600): " findtime
    findtime=${findtime:-600}
    
    read -rp "Путь к лог-файлу (по умолчанию: /var/log/auth.log): " logpath
    logpath=${logpath:-/var/log/auth.log}
    
    # Создаем директорию для конфигураций jail если её нет
    mkdir -p "$FAIL2BAN_JAIL_DIR"
    
    # Создаем конфигурационный файл для jail
    local config_file="$FAIL2BAN_JAIL_DIR/${jail_name}.local"
    cat > "$config_file" << EOF
[$jail_name]
enabled = true
port = $jail_port
protocol = $jail_protocol
filter = $jail_name
logpath = $logpath
maxretry = $maxretry
bantime = $bantime
findtime = $findtime
action = ufw[name=UFW, port="\$(port)", protocol="\$(protocol)"]
EOF
    
    # Создаем фильтр для jail
    local filter_file="/etc/fail2ban/filter.d/${jail_name}.conf"
    cat > "$filter_file" << EOF
[Definition]
failregex = ^.*Failed password for .* from <HOST> port .*$
            ^.*Invalid user .* from <HOST> port .*$
            ^.*authentication failure.*rhost=<HOST>.*$
ignoreregex =
EOF
    
    # Перезагружаем fail2ban
    echo "🔄 Перезагрузка fail2ban..."
    systemctl restart fail2ban 2>/dev/null || systemctl reload fail2ban 2>/dev/null
    
    echo ""
    echo "✅ Jail '$jail_name' успешно создан"
    echo "📁 Конфигурация: $config_file"
    echo "📁 Фильтр: $filter_file"
    echo "📊 Порт: $jail_port"
    echo "📊 Протокол: $jail_protocol"
    echo "📊 Время блокировки: $bantime сек"
    echo "📊 Макс. попыток: $maxretry"
}

# Удаление jail
delete_fail2ban_jail() {
    if ! fail2ban_installed; then
        echo "❌ fail2ban не установлен"
        pause
        return
    fi
    
    echo "➖ Удаление Fail2ban Jail"
    echo ""
    
    # Получаем список jails
    local jails_list=$(get_fail2ban_jails)
    if [[ -z "$jails_list" ]]; then
        echo "❌ Нет доступных jails для удаления"
        pause
        return
    fi
    
    # Показываем список jails с номерами
    echo "Список доступных jails:"
    echo "------------------------"
    local jails=()
    local i=1
    for jail in $jails_list; do
        echo "$i. $jail"
        jails[$i]="$jail"
        ((i++))
    done
    echo ""
    
    read -rp "Введите номер jail для удаления: " jail_num
    if [[ ! "$jail_num" =~ ^[0-9]+$ ]]; then
        echo "❌ Неверный номер"
        pause
        return
    fi
    
    if [[ -z "${jails[$jail_num]}" ]]; then
        echo "❌ Jail не найден"
        pause
        return
    fi
    
    local jail_name="${jails[$jail_num]}"
    
    if [[ "$jail_name" == "sshd" ]]; then
        echo "❌ Нельзя удалить системный jail 'sshd'"
        pause
        return
    fi
    
    # Подтверждение удаления
    echo ""
    read -rp "Вы уверены, что хотите удалить jail '$jail_name'? (y/N): " confirm
    if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
        echo "Отменено"
        pause
        return
    fi
    
    # Отключаем jail
    fail2ban-client stop "$jail_name" >/dev/null 2>&1
    
    # Удаляем конфигурационные файлы
    rm -f "$FAIL2BAN_JAIL_DIR/${jail_name}.local" 2>/dev/null
    rm -f "/etc/fail2ban/filter.d/${jail_name}.conf" 2>/dev/null
    
    # Перезагружаем fail2ban
    systemctl reload fail2ban 2>/dev/null
    
    echo "✅ Jail '$jail_name' успешно удален"
}

# Редактирование параметров jail
edit_fail2ban_jail() {
    if ! fail2ban_installed; then
        echo "❌ fail2ban не установлен"
        pause
        return
    fi
    
    echo "✏️ Редактирование Fail2ban Jail"
    echo ""
    
    # Получаем список jails
    local jails_list=$(get_fail2ban_jails)
    if [[ -z "$jails_list" ]]; then
        echo "❌ Нет доступных jails для редактирования"
        pause
        return
    fi
    
    # Показываем список jails с номерами
    echo "Список доступных jails:"
    echo "------------------------"
    local jails=()
    local i=1
    for jail in $jails_list; do
        echo "$i. $jail"
        jails[$i]="$jail"
        ((i++))
    done
    echo ""
    
    read -rp "Введите номер jail для редактирования: " jail_num
    if [[ ! "$jail_num" =~ ^[0-9]+$ ]]; then
        echo "❌ Неверный номер"
        pause
        return
    fi
    
    if [[ -z "${jails[$jail_num]}" ]]; then
        echo "❌ Jail не найден"
        pause
        return
    fi
    
    local jail_name="${jails[$jail_num]}"
    local config_file="$FAIL2BAN_JAIL_DIR/${jail_name}.local"
    
    # Если нет отдельного конфига, используем основной
    if [[ ! -f "$config_file" ]]; then
        config_file="$FAIL2BAN_LOCAL_CONFIG"
        if [[ ! -f "$config_file" ]]; then
            echo "❌ Конфигурационный файл не найден"
            pause
            return
        fi
    fi
    
    echo ""
    echo "Текущие параметры jail '$jail_name':"
    echo "------------------------------------"
    grep -E "^(port|protocol|maxretry|bantime|findtime|enabled)" "$config_file" | head -10
    
    echo ""
    echo "Выберите параметр для редактирования:"
    echo "1. Порт"
    echo "2. Протокол"
    echo "3. Максимальное количество попыток (maxretry)"
    echo "4. Время блокировки (bantime)"
    echo "5. Время поиска (findtime)"
    echo "6. Включен/выключен (enabled)"
    echo "0. Отмена"
    echo ""
    
    read -rp "Выбор: " param_choice
    
    case $param_choice in
        1)
            read -rp "Новый порт (например: 22,80,443 или all): " new_port
            if [[ -n "$new_port" ]]; then
                sed -i "s/^port = .*/port = $new_port/" "$config_file" 2>/dev/null
                echo "✅ Порт обновлен"
            fi
            ;;
        2)
            read -rp "Новый протокол (tcp/udp): " new_protocol
            if [[ -n "$new_protocol" ]]; then
                sed -i "s/^protocol = .*/protocol = $new_protocol/" "$config_file" 2>/dev/null
                echo "✅ Протокол обновлен"
            fi
            ;;
        3)
            read -rp "Новое значение maxretry: " new_maxretry
            if [[ -n "$new_maxretry" && "$new_maxretry" =~ ^[0-9]+$ ]]; then
                sed -i "s/^maxretry = .*/maxretry = $new_maxretry/" "$config_file" 2>/dev/null
                echo "✅ Maxretry обновлен"
            else
                echo "❌ Некорректное значение"
            fi
            ;;
        4)
            read -rp "Новое значение bantime (в секундах): " new_bantime
            if [[ -n "$new_bantime" && "$new_bantime" =~ ^[0-9]+$ ]]; then
                sed -i "s/^bantime = .*/bantime = $new_bantime/" "$config_file" 2>/dev/null
                echo "✅ Bantime обновлен"
            else
                echo "❌ Некорректное значение"
            fi
            ;;
        5)
            read -rp "Новое значение findtime (в секундах): " new_findtime
            if [[ -n "$new_findtime" && "$new_findtime" =~ ^[0-9]+$ ]]; then
                sed -i "s/^findtime = .*/findtime = $new_findtime/" "$config_file" 2>/dev/null
                echo "✅ Findtime обновлен"
            else
                echo "❌ Некорректное значение"
            fi
            ;;
        6)
            echo "Текущее значение: $(grep '^enabled = ' "$config_file" 2>/dev/null || echo 'enabled = true')"
            read -rp "Включить jail? (y/n): " enable_choice
            if [[ "$enable_choice" == "y" || "$enable_choice" == "Y" ]]; then
                sed -i "s/^enabled = .*/enabled = true/" "$config_file" 2>/dev/null
                echo "✅ Jail включен"
            elif [[ "$enable_choice" == "n" || "$enable_choice" == "N" ]]; then
                sed -i "s/^enabled = .*/enabled = false/" "$config_file" 2>/dev/null
                echo "✅ Jail выключен"
            fi
            ;;
        0)
            echo "Отменено"
            return
            ;;
        *)
            echo "❌ Неверный выбор"
            pause
            return
            ;;
    esac
    
    # Перезагружаем fail2ban
    echo "🔄 Перезагрузка fail2ban..."
    systemctl reload fail2ban 2>/dev/null
    
    echo "✅ Параметры jail '$jail_name' успешно обновлены"
}

# Управление правилами fail2ban для конкретного jail
manage_fail2ban_jail_rules() {
    if ! fail2ban_installed; then
        echo "❌ fail2ban не установлен"
        pause
        return
    fi
    
    echo "🛡 Управление правилами Fail2ban Jail"
    echo ""
    
    # Получаем список jails
    local jails_list=$(get_fail2ban_jails)
    if [[ -z "$jails_list" ]]; then
        echo "❌ Нет доступных jails"
        pause
        return
    fi
    
    # Показываем список jails с номерами
    echo "Список доступных jails:"
    echo "------------------------"
    local jails=()
    local i=1
    for jail in $jails_list; do
        echo "$i. $jail"
        jails[$i]="$jail"
        ((i++))
    done
    echo ""
    
    read -rp "Введите номер jail: " jail_num
    if [[ ! "$jail_num" =~ ^[0-9]+$ ]]; then
        echo "❌ Неверный номер"
        pause
        return
    fi
    
    if [[ -z "${jails[$jail_num]}" ]]; then
        echo "❌ Jail не найден"
        pause
        return
    fi
    
    local jail_name="${jails[$jail_num]}"
    
    echo ""
    echo "Управление jail: $jail_name"
    echo "------------------------------"
    echo "1. Показать заблокированные IP"
    echo "2. Разблокировать конкретный IP"
    echo "3. Разблокировать все IP"
    echo "4. Включить jail"
    echo "5. Выключить jail"
    echo "6. Проверить статус jail"
    echo "0. Назад"
    echo ""
    
    read -rp "Выбор: " action_choice
    
    case $action_choice in
        1)
            echo "Заблокированные IP для $jail_name:"
            echo "----------------------------------"
            fail2ban-client status "$jail_name" | grep -A 100 "Banned IP list:" | head -20
            ;;
        2)
            read -rp "Введите IP для разблокировки: " ip_to_unban
            if [[ -n "$ip_to_unban" ]]; then
                if fail2ban-client set "$jail_name" unbanip "$ip_to_unban" 2>/dev/null; then
                    echo "✅ IP $ip_to_unban разблокирован в $jail_name"
                else
                    echo "❌ Ошибка при разблокировке IP"
                fi
            fi
            ;;
        3)
            read -rp "Вы уверены, что хотите разблокировать все IP в $jail_name? (y/N): " confirm
            if [[ "$confirm" == "y" || "$confirm" == "Y" ]]; then
                if fail2ban-client set "$jail_name" unban --all 2>/dev/null; then
                    echo "✅ Все IP разблокированы в $jail_name"
                else
                    echo "❌ Ошибка при разблокировке"
                fi
            else
                echo "Отменено"
            fi
            ;;
        4)
            if fail2ban-client start "$jail_name" 2>/dev/null; then
                echo "✅ Jail $jail_name включен"
            else
                echo "❌ Ошибка при включении jail"
            fi
            ;;
        5)
            if fail2ban-client stop "$jail_name" 2>/dev/null; then
                echo "✅ Jail $jail_name выключен"
            else
                echo "❌ Ошибка при выключении jail"
            fi
            ;;
        6)
            echo "Статус $jail_name:"
            echo "-------------------"
            fail2ban-client status "$jail_name" | head -15
            ;;
        0)
            return
            ;;
        *)
            echo "❌ Неверный выбор"
            ;;
    esac
}

# Установка/удаление Fail2ban с созданием дефолтных jails
fail2ban_manage() {
    echo "🛠 Установка/Удаление Fail2ban"
    echo ""
    echo "1. Установить Fail2ban"
    echo "2. Удалить Fail2ban"
    echo "0. Назад"
    echo ""
    
    read -rp "Выбор: " c
    
    case $c in
        1)
            echo "🔹 Установка Fail2ban..."
            echo ""
            
            # Проверяем, не установлен ли уже fail2ban
            if fail2ban_installed; then
                echo "⚠️ Fail2ban уже установлен"
                pause
                return
            fi
            
            # Обновляем пакеты и устанавливаем fail2ban
            echo "🔄 Обновление пакетов..."
            apt update >/dev/null 2>&1
            
            echo "📦 Установка fail2ban..."
            if apt install -y fail2ban >/dev/null 2>&1; then
                echo "✅ Fail2ban успешно установлен"
                
                # Создаем базовую конфигурацию если её нет
                if [[ ! -f "$FAIL2BAN_LOCAL_CONFIG" ]]; then
                    echo "📝 Создание базовой конфигурации..."
                    cat > "$FAIL2BAN_LOCAL_CONFIG" << EOF
[DEFAULT]
bantime = 600
findtime = 600
maxretry = 3
destemail = root@localhost
sender = root@localhost
mta = sendmail
action = %(action_)s

[sshd]
enabled = true
port = ssh
logpath = %(sshd_log)s
maxretry = 3
bantime = 600
EOF
                    echo "✅ Базовая конфигурация создана"
                fi
                
                # Создаем директорию для кастомных jail если её нет
                mkdir -p "$FAIL2BAN_JAIL_DIR"
                
                # Создаем дефолтные jails для HTTP и HTTPS
                create_default_http_jails
                
                # Запускаем fail2ban
                echo "🚀 Запуск службы fail2ban..."
                systemctl enable --now fail2ban >/dev/null 2>&1
                sleep 2
                
                # Проверяем статус
                if systemctl is-active --quiet fail2ban; then
                    echo "✅ Служба fail2ban запущена"
                    echo ""
                    echo "📊 Созданные jails:"
                    echo "-------------------"
                    local jails=$(get_fail2ban_jails)
                    if [[ -n "$jails" ]]; then
                        echo "$jails" | tr ' ' '\n'
                        echo ""
                        echo "🌐 Дефолтные jails для HTTP/HTTPS готовы к работе"
                    fi
                else
                    echo "⚠️ Служба fail2ban не запустилась автоматически"
                    echo "Попробуйте запустить вручную: systemctl start fail2ban"
                fi
            else
                echo "❌ Ошибка при установке fail2ban"
                echo "Попробуйте установить вручную: apt install fail2ban"
            fi
            ;;
        2)
            echo "🔹 Удаление Fail2ban..."
            echo ""
            
            if ! fail2ban_installed; then
                echo "⚠️ Fail2ban не установлен"
                pause
                return
            fi
            
            read -rp "Вы уверены, что хотите удалить fail2ban? (y/N): " confirm
            if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
                echo "Отменено"
                pause
                return
            fi
            
            echo "🛑 Остановка службы..."
            systemctl stop fail2ban >/dev/null 2>&1
            systemctl disable fail2ban >/dev/null 2>&1
            
            echo "🗑️ Удаление fail2ban..."
            if apt remove -y fail2ban >/dev/null 2>&1; then
                apt autoremove -y >/dev/null 2>&1
                echo "✅ Fail2ban удалён"
            else
                echo "❌ Ошибка при удалении fail2ban"
            fi
            ;;
        0)
            return
            ;;
        *)
            echo "❌ Неверный выбор"
            ;;
    esac
}

# Меню проверки правил
check_rules_menu() {
    clear
    echo "📋 Проверка текущих правил UFW"
    echo "================================"
    echo ""
    ufw status verbose
    echo ""
    echo "1. Добавить правила"
    echo "2. Удалить правила"
    echo "0. Назад"
    echo ""
    
    read -rp "Выбор: " c
    
    case $c in
        1) add_rules_menu ;;
        2) delete_rules_menu ;;
        0) return ;;
        *) echo "❌ Неверный выбор" && pause ;;
    esac
}

# Меню добавления правил
add_rules_menu() {
    clear
    echo "➕ Добавление правил UFW"
    echo "========================"
    echo ""
    echo "1. Типовые (SSH, HTTP, HTTPS)"
    echo "2. Из rules.config"
    echo "3. Вручную"
    echo "0. Назад"
    echo ""
    
    read -rp "Выбор: " c
    
    case $c in
        1)
            echo ""
            echo "Добавление типовых правил..."
            apply_rule IN 22 tcp
            apply_rule IN 80 tcp
            apply_rule IN 443 tcp
            echo "✅ Типовые правила добавлены"
            ;;
        2)
            echo ""
            if [[ ! -f "$RULES_FILE" ]]; then
                echo "❌ Файл $RULES_FILE не найден"
                echo "Создаю файл с правилами по умолчанию..."
                init_rules_file
                echo "Теперь можно добавить правила из файла"
            else
                echo "Добавление правил из $RULES_FILE..."
                while IFS=":" read -r name dir port proto; do
                    [[ -n "$name" && -n "$dir" && -n "$port" && -n "$proto" ]] && apply_rule "$dir" "$port" "$proto"
                done < "$RULES_FILE"
                echo "✅ Правила из файла добавлены"
            fi
            ;;
        3)
            echo ""
            echo "Ручное добавление правила:"
            echo "--------------------------"
            
            read -rp "Имя правила (опционально): " name
            name=${name:-custom_rule}
            
            read -rp "Направление (IN/OUT/BOTH): " dir
            if ! validate_direction "$dir"; then
                echo "❌ Неверное направление. Используйте IN, OUT или BOTH"
                pause
                return
            fi
            
            read -rp "Порт (1-65535): " port
            if ! validate_port "$port"; then
                echo "❌ Неверный порт. Должен быть от 1 до 65535"
                pause
                return
            fi
            
            read -rp "Протокол (tcp/udp/both): " proto
            if ! validate_protocol "$proto"; then
                echo "❌ Неверный протокол. Используйте tcp, udp или both"
                pause
                return
            fi
            
            apply_rule "$dir" "$port" "$proto"
            
            # Добавляем правило в конфиг файл если его там нет
            if ! config_rule_exists "$dir" "$port" "$proto"; then
                echo "$name:$dir:$port:$proto" >> "$RULES_FILE"
                echo "✅ Правило добавлено в $RULES_FILE"
            fi
            ;;
        0)
            return
            ;;
        *)
            echo "❌ Неверный выбор"
            ;;
    esac
    
    pause
}

# Меню удаления правил
delete_rules_menu() {
    clear
    echo "➖ Удаление правил UFW"
    echo "======================"
    echo ""
    echo "1. Типовые (HTTP, HTTPS)"
    echo "2. Из rules.config"
    echo "3. По номеру (SSH защищён)"
    echo "0. Назад"
    echo ""
    
    read -rp "Выбор: " c
    
    case $c in
        1)
            echo ""
            echo "Удаление типовых правил..."
            delete_rule IN 80 tcp
            delete_rule IN 443 tcp
            echo "✅ Типовые правила удалены"
            ;;
        2)
            echo ""
            if [[ ! -f "$RULES_FILE" ]]; then
                echo "❌ Файл $RULES_FILE не найден"
            else
                echo "Удаление правил из $RULES_FILE..."
                while IFS=":" read -r name dir port proto; do
                    [[ -n "$name" && -n "$dir" && -n "$port" && -n "$proto" ]] && delete_rule "$dir" "$port" "$proto"
                done < "$RULES_FILE"
                echo "✅ Правила из файла удалены"
            fi
            ;;
        3)
            echo ""
            echo "Текущие правила UFW с номерами:"
            echo "--------------------------------"
            ufw status numbered
            echo ""
            
            read -rp "Введите номер правила для удаления: " num
            if [[ ! "$num" =~ ^[0-9]+$ ]]; then
                echo "❌ Неверный номер"
            else
                # Проверяем, не SSH ли это правило
                rule=$(ufw status numbered | grep "^\[$num\]" | sed "s/^\[$num\]//")
                if echo "$rule" | grep -q "22/tcp.*ALLOW"; then
                    echo "❌ SSH удалять нельзя"
                else
                    ufw delete "$num" >/dev/null 2>&1
                    echo "✅ Правило №$num удалено"
                fi
            fi
            ;;
        0)
            return
            ;;
        *)
            echo "❌ Неверный выбор"
            ;;
    esac
    
    pause
}

# Меню редактирования rules.config
edit_rules_file_menu() {
    clear
    echo "✏️ Редактирование rules.config"
    echo "============================="
    echo ""
    echo "1. Показать правила"
    echo "2. Добавить правило"
    echo "3. Удалить правило"
    echo "0. Назад"
    echo ""
    
    read -rp "Выбор: " c
    
    case $c in
        1)
            echo ""
            echo "Содержимое $RULES_FILE:"
            echo "-----------------------"
            if [[ -f "$RULES_FILE" && -s "$RULES_FILE" ]]; then
                nl -w2 -s'. ' "$RULES_FILE"
            else
                echo "Файл пуст или не существует"
                echo "Создать файл с правилами по умолчанию? (y/N): "
                read -rp "" create_choice
                if [[ "$create_choice" == "y" || "$create_choice" == "Y" ]]; then
                    init_rules_file
                fi
            fi
            ;;
        2)
            echo ""
            echo "Добавление нового правила:"
            echo "--------------------------"
            
            read -rp "Имя правила: " name
            [[ -z "$name" ]] && { echo "❌ Имя не может быть пустым"; pause; return; }
            
            read -rp "Направление (IN/OUT/BOTH): " dir
            if ! validate_direction "$dir"; then
                echo "❌ Неверное направление"
                pause
                return
            fi
            
            read -rp "Порт (1-65535): " port
            if ! validate_port "$port"; then
                echo "❌ Неверный порт"
                pause
                return
            fi
            
            read -rp "Протокол (tcp/udp/both): " proto
            if ! validate_protocol "$proto"; then
                echo "❌ Неверный протокол"
                pause
                return
            fi
            
            if config_rule_exists "$dir" "$port" "$proto"; then
                echo "⚠️ Такое правило уже существует"
            else
                echo "$name:$dir:$port:$proto" >> "$RULES_FILE"
                echo "✅ Правило добавлено"
            fi
            ;;
        3)
            echo ""
            if [[ ! -f "$RULES_FILE" || ! -s "$RULES_FILE" ]]; then
                echo "❌ Файл пуст или не существует"
            else
                echo "Текущие правила:"
                echo "----------------"
                nl -w2 -s'. ' "$RULES_FILE"
                echo ""
                
                read -rp "Введите номер строки для удаления: " line
                if [[ ! "$line" =~ ^[0-9]+$ ]]; then
                    echo "❌ Неверный номер"
                elif [[ "$line" -gt 0 && "$line" -le $(wc -l < "$RULES_FILE") ]]; then
                    # Проверяем, не SSH ли это правило
                    rule=$(sed -n "${line}p" "$RULES_FILE")
                    if echo "$rule" | grep -q ":22:tcp$"; then
                        echo "❌ SSH удалять нельзя"
                    else
                        sed -i "${line}d" "$RULES_FILE"
                        echo "✅ Строка $line удалена"
                    fi
                else
                    echo "❌ Неверный номер строки"
                fi
            fi
            ;;
        0)
            return
            ;;
        *)
            echo "❌ Неверный выбор"
            ;;
    esac
    
    pause
}

# Главное меню Fail2ban
fail2ban_menu() {
    while true; do
        clear
        echo "🛡 Управление Fail2ban"
        echo "====================="
        echo ""
        echo "1. Проверить статус Fail2ban"
        echo "2. Показать активные jails"
        echo "3. Создать новый jail"
        echo "4. Удалить jail"
        echo "5. Редактировать параметры jail"
        echo "6. Управление правилами конкретного jail"
        echo "7. Создать UFW-правила для всех jails"
        echo "8. Автосинхронизация с UFW"
        echo "9. Разблокировать IP во всех jails"
        echo "10. Установить/Удалить Fail2ban"
        echo "0. Назад в главное меню"
        echo ""
        
        read -rp "Выбор: " c
        
        case $c in
            1) 
                clear
                fail2ban_status
                pause
                ;;
            2) 
                clear
                echo "📊 Активные jails:"
                echo "=================="
                local jails=$(get_fail2ban_jails)
                if [[ -n "$jails" ]]; then
                    echo "$jails" | tr ' ' '\n' | nl -w2 -s'. '
                else
                    echo "Нет активных jails"
                    if ! fail2ban_installed; then
                        echo "⚠️ Fail2ban не установлен. Установите через пункт 10"
                    fi
                fi
                pause
                ;;
            3) 
                clear
                create_fail2ban_jail
                pause
                ;;
            4) 
                clear
                delete_fail2ban_jail
                pause
                ;;
            5) 
                clear
                edit_fail2ban_jail
                pause
                ;;
            6) 
                clear
                manage_fail2ban_jail_rules
                pause
                ;;
            7) 
                clear
                echo "🔄 Создание UFW правил для всех jails..."
                local jails=$(get_fail2ban_jails)
                if [[ -n "$jails" ]]; then
                    for jail in $jails; do
                        create_ufw_rule_from_jail "$jail"
                    done
                    echo "✅ Правила созданы"
                else
                    echo "⚠️ Нет активных jails"
                fi
                pause
                ;;
            8) 
                clear
                fail2ban_autosync
                pause
                ;;
            9) 
                clear
                fail2ban_unban_ip
                pause
                ;;
            10) 
                clear
                fail2ban_manage
                pause
                ;;
            0) 
                return
                ;;
            *) 
                echo "❌ Неверный выбор"
                pause
                ;;
        esac
    done
}

# Главное меню
main_menu() {
    while true; do
        clear
        echo "🔥 UFW Manager с интеграцией Fail2ban"
        echo "===================================="
        echo ""
        echo "1. Проверка текущих правил UFW"
        echo "2. Добавление правил UFW"
        echo "3. Удаление правил UFW"
        echo "4. Редактирование списка правил (rules.config)"
        echo "5. Управление Fail2ban"
        echo "0. Выход"
        echo ""
        
        read -rp "Выбор: " c
        
        case $c in
            1) check_rules_menu ;;
            2) add_rules_menu ;;
            3) delete_rules_menu ;;
            4) edit_rules_file_menu ;;
            5) fail2ban_menu ;;
            0) 
                clear
                echo "Выход из UFW Manager..."
                echo ""
                exit 0
                ;;
            *) 
                echo "❌ Неверный выбор"
                pause
                ;;
        esac
    done
}

# Основной запуск
echo "=========================================="
echo "🔥 Запуск UFW Manager с интеграцией Fail2ban"
echo "=========================================="
echo ""

check_root
init_rules_file

# Проверяем, включен ли UFW
if ! systemctl is-active --quiet ufw 2>/dev/null; then
    echo "⚠️ UFW не активен. Включаю..."
    ufw --force enable >/dev/null 2>&1
    echo "✅ UFW включен"
    sleep 1
fi

echo "✅ Система готова к работе"
echo ""
main_menu