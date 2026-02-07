#!/bin/bash
RULES_FILE="rules.config"
SSH_PORT=22
SSH_PROTO="tcp"

pause() { read -rp "Нажмите Enter для продолжения..."; }
check_root() { [[ $EUID -ne 0 ]] && echo "❌ Запустите скрипт от root" && exit 1; }
validate_port() { [[ "$1" =~ ^[0-9]+$ ]] && (( $1 >= 1 && $1 <= 65535 )); }
validate_protocol() { [[ "$1" == "tcp" || "$1" == "udp" || "$1" == "both" ]]; }
validate_direction() { [[ "$1" == "IN" || "$1" == "OUT" || "$1" == "BOTH" ]]; }
ufw_rule_exists() { ufw status | grep -qw "$1/$2"; }
config_rule_exists() { grep -q ":$1:$2:$3$" "$RULES_FILE"; }

populate_default_rules() {
  local defaults=("SSH:IN:22:tcp" "HTTP:IN:80:tcp" "HTTPS:IN:443:tcp")
  for rule in "${defaults[@]}"; do
    IFS=":" read -r name dir port proto <<< "$rule"
    if ! config_rule_exists "$dir" "$port" "$proto"; then
      echo "$rule" >> "$RULES_FILE"
    fi
  done
}

init_rules_file() { [[ ! -f "$RULES_FILE" ]] && touch "$RULES_FILE" && populate_default_rules; }

apply_rule() {
  local dir=$1 port=$2 proto=$3
  [[ "$proto" == "both" ]] && { apply_rule "$dir" "$port" tcp; apply_rule "$dir" "$port" udp; return; }
  ufw_rule_exists "$port" "$proto" && { echo "⚠️ $dir $port/$proto уже существует"; return; }
  case "$dir" in
    IN) ufw allow "$port/$proto" ;;
    OUT) ufw allow out "$port/$proto" ;;
    BOTH) ufw allow "$port/$proto"; ufw allow out "$port/$proto";;
  esac
}

delete_rule() {
  local dir=$1 port=$2 proto=$3
  [[ "$port" == "$SSH_PORT" && "$proto" == "$SSH_PROTO" ]] && { echo "❌ Удаление SSH запрещено"; return; }
  [[ "$proto" == "both" ]] && { delete_rule "$dir" "$port" tcp; delete_rule "$dir" "$port" udp; return; }
  case "$dir" in
    IN) ufw delete allow "$port/$proto" ;;
    OUT) ufw delete allow out "$port/$proto" ;;
    BOTH) ufw delete allow "$port/$proto"; ufw delete allow out "$port/$proto";;
  esac
}

fail2ban_installed() { command -v fail2ban-client >/dev/null 2>&1; }
fail2ban_status() { fail2ban_installed || { echo "❌ fail2ban не установлен"; return; }; systemctl status fail2ban --no-pager; }
get_fail2ban_jails() { fail2ban-client status 2>/dev/null | grep "Jail list" | sed 's/.*Jail list:\s*//' | tr ',' ' '; }
get_jail_port_proto() { local jail=$1; local port proto; port=$(fail2ban-client get "$jail" port 2>/dev/null); proto=$(fail2ban-client get "$jail" protocol 2>/dev/null); [[ "$proto" == "" ]] && proto="tcp"; echo "$port:$proto"; }
create_ufw_rule_from_jail() {
  local jail=$1 port proto
  IFS=":" read -r port proto <<< "$(get_jail_port_proto "$jail")"
  [[ -z "$port" ]] && { echo "⚠️ Не удалось определить порт для $jail"; return; }
  ufw_rule_exists "$port" "$proto" && { echo "⚠️ UFW правило для $jail уже существует"; return; }
  echo "➕ Добавление UFW правила для jail $jail ($port/$proto)"
  ufw allow "$port/$proto"
  ! config_rule_exists "IN" "$port" "$proto" && echo "fail2ban-$jail:IN:$port:$proto" >> "$RULES_FILE"
}

fail2ban_autosync() { for jail in $(get_fail2ban_jails); do create_ufw_rule_from_jail "$jail"; done; }
fail2ban_unban_ip() {
  fail2ban_installed || { echo "❌ fail2ban не установлен"; return; }
  read -rp "Введите IP для разблокировки: " ip
  [[ -z "$ip" ]] && { echo "❌ IP не указан"; return; }
  jails=$(get_fail2ban_jails)
  for jail in $jails; do
    fail2ban-client set "$jail" unbanip "$ip" 2>/dev/null && echo "✅ $ip разблокирован в $jail" || echo "⚠️ $ip не найден в $jail"
  done
}

fail2ban_manage() {
    echo "🛠 Управление Fail2ban"
    echo "1. Установить Fail2ban"
    echo "2. Удалить Fail2ban"
    echo "0. Назад"
    read -rp "Выбор: " c

    case $c in
        1)
            echo "🔹 Установка Fail2ban..."
            apt update && apt install -y fail2ban
            systemctl enable --now fail2ban
            echo "✅ Fail2ban установлен и запущен"
            ;;
        2)
            echo "🔹 Удаление Fail2ban..."
            systemctl stop fail2ban
            apt remove -y fail2ban
            apt autoremove -y
            echo "✅ Fail2ban удалён"
            ;;
        0) return ;;
    esac
    pause
}

check_rules_menu() {
  clear; ufw status verbose
  echo "1. Добавить правила"; echo "2. Удалить правила"; echo "0. Назад"
  read -rp "Выбор: " c; [[ "$c" == "1" ]] && add_rules_menu; [[ "$c" == "2" ]] && delete_rules_menu
}
add_rules_menu() {
  clear
  echo "➕ Добавление"; echo "1. Типовые (SSH, HTTP, HTTPS)"; echo "2. Из rules.config"; echo "3. Вручную"; echo "0. Назад"
  read -rp "Выбор: " c
  case $c in
    1) apply_rule IN 22 tcp; apply_rule IN 80 tcp; apply_rule IN 443 tcp;;
    2) while IFS=":" read -r name dir port proto; do apply_rule "$dir" "$port" "$proto"; done < "$RULES_FILE";;
    3)
      read -rp "Имя: " name; read -rp "Направление (IN/OUT/BOTH): " dir; validate_direction "$dir" || return
      read -rp "Порт: " port; validate_port "$port" || return
      read -rp "Протокол (tcp/udp/both): " proto; validate_protocol "$proto" || return
      apply_rule "$dir" "$port" "$proto";;
  esac; pause
}
delete_rules_menu() {
  clear; echo "➖ Удаление"; echo "1. Типовые (HTTP, HTTPS)"; echo "2. Из rules.config"; echo "3. По номеру (SSH защищён)"; echo "0. Назад"; read -rp "Выбор: " c
  case $c in
    1) delete_rule IN 80 tcp; delete_rule IN 443 tcp;;
    2) while IFS=":" read -r name dir port proto; do delete_rule "$dir" "$port" "$proto"; done < "$RULES_FILE";;
    3) ufw status numbered; read -rp "Номер: " num; rule=$(ufw status numbered | sed -n "${num}p"); echo "$rule" | grep -q "22/tcp" && echo "❌ SSH удалять нельзя" || ufw delete "$num";;
  esac; pause
}
edit_rules_file_menu() {
  clear; echo "✏️ rules.config"; echo "1. Показать"; echo "2. Добавить"; echo "3. Удалить"; echo "0. Назад"; read -rp "Выбор: " c
  case $c in
    1) nl -w2 -s'. ' "$RULES_FILE";;
    2)
      read -rp "Имя: " name; read -rp "Направление: " dir; validate_direction "$dir" || return
      read -rp "Порт: " port; validate_port "$port" || return
      read -rp "Протокол: " proto; validate_protocol "$proto" || return
      config_rule_exists "$dir" "$port" "$proto" && echo "⚠️ Дубликат" || echo "$name:$dir:$port:$proto" >> "$RULES_FILE";;
    3) nl -w2 -s'. ' "$RULES_FILE"; read -rp "Строка: " line; sed -i "${line}d" "$RULES_FILE";;
  esac; pause
}
fail2ban_menu() {
    clear
    echo "🛡 Fail2ban"
    echo "1. Проверить статус"
    echo "2. Показать активные jail"
    echo "3. Создать UFW-правила для jail"
    echo "4. Автосинхронизация (рекомендуется)"
    echo "5. Разблокировать IP"
    echo "6. Установить/Удалить Fail2ban"
    echo "0. Назад"
    read -rp "Выбор: " c

    case $c in
        1) fail2ban_status ;;
        2) get_fail2ban_jails | tr ' ' '\n' ;;
        3) for jail in $(get_fail2ban_jails); do create_ufw_rule_from_jail "$jail"; done ;;
        4) fail2ban_autosync ;;
        5) fail2ban_unban_ip ;;
        6) fail2ban_manage ;;
    esac
    pause
}

main_menu() {
  while true; do
    clear
    echo "🔥 UFW Manager"
    echo "1. Проверка текущих правил"; echo "2. Добавление правил"; echo "3. Удаление правил"; echo "4. Редактирование списка правил"; echo "5. Интеграция с Fail2ban"; echo "0. Выход"
    read -rp "Выбор: " c
    case $c in 1) check_rules_menu;; 2) add_rules_menu;; 3) delete_rules_menu;; 4) edit_rules_file_menu;; 5) fail2ban_menu;; 0) exit 0;; esac
  done
}

check_root
init_rules_file
main_menu
