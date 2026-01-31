#!/bin/bash

RULES_FILE="rules.config"
SSH_PORT=22
SSH_PROTO="tcp"

# ---------- Общие ----------
pause() {
    read -rp "Нажмите Enter для продолжения..."
}

check_root() {
    [[ $EUID -ne 0 ]] && echo "❌ Запустите скрипт от root" && exit 1
}

# ---------- Валидация ----------
validate_port() {
    [[ "$1" =~ ^[0-9]+$ ]] && (( $1 >= 1 && $1 <= 65535 ))
}

validate_protocol() {
    [[ "$1" == "tcp" || "$1" == "udp" || "$1" == "both" ]]
}

validate_direction() {
    [[ "$1" == "IN" || "$1" == "OUT" || "$1" == "BOTH" ]]
}

# ---------- Проверка дубликатов ----------
ufw_rule_exists() {
    ufw status | grep -qw "$1/$2"
}

config_rule_exists() {
    grep -q ":$1:$2:$3$" "$RULES_FILE"
}

# ---------- Автозаполнение ----------
populate_default_rules() {
    echo "📌 Автозаполнение типовых правил"

    local defaults=(
        "SSH:IN:22:tcp"
        "HTTP:IN:80:tcp"
        "HTTPS:IN:443:tcp"
    )

    for rule in "${defaults[@]}"; do
        IFS=":" read -r name dir port proto <<< "$rule"
        if ! config_rule_exists "$dir" "$port" "$proto"; then
            echo "$rule" >> "$RULES_FILE"
            echo "  ➕ $rule"
        fi
    done
}

init_rules_file() {
    if [[ ! -f "$RULES_FILE" ]]; then
        touch "$RULES_FILE"
        echo "📄 Создан $RULES_FILE"
        populate_default_rules
        sleep 1
    fi
}

# ---------- Работа с UFW ----------
apply_rule() {
    local dir=$1 port=$2 proto=$3

    if [[ "$proto" == "both" ]]; then
        apply_rule "$dir" "$port" tcp
        apply_rule "$dir" "$port" udp
        return
    fi

    ufw_rule_exists "$port" "$proto" && {
        echo "⚠️ $dir $port/$proto уже существует"
        return
    }

    case "$dir" in
        IN) ufw allow "$port/$proto" ;;
        OUT) ufw allow out "$port/$proto" ;;
        BOTH)
            ufw allow "$port/$proto"
            ufw allow out "$port/$proto"
            ;;
    esac
}

delete_rule() {
    local dir=$1 port=$2 proto=$3

    [[ "$port" == "$SSH_PORT" && "$proto" == "$SSH_PROTO" ]] && {
        echo "❌ Удаление SSH запрещено"
        return
    }

    if [[ "$proto" == "both" ]]; then
        delete_rule "$dir" "$port" tcp
        delete_rule "$dir" "$port" udp
        return
    fi

    case "$dir" in
        IN) ufw delete allow "$port/$proto" ;;
        OUT) ufw delete allow out "$port/$proto" ;;
        BOTH)
            ufw delete allow "$port/$proto"
            ufw delete allow out "$port/$proto"
            ;;
    esac
}

# ---------- Меню ----------
check_rules_menu() {
    clear
    ufw status verbose
    echo
    echo "1. Добавить правила"
    echo "2. Удалить правила"
    echo "0. Назад"
    read -rp "Выбор: " c
    [[ "$c" == "1" ]] && add_rules_menu
    [[ "$c" == "2" ]] && delete_rules_menu
}

add_rules_menu() {
    clear
    echo "➕ Добавление"
    echo "1. Типовые (SSH, HTTP, HTTPS)"
    echo "2. Из rules.config"
    echo "3. Вручную"
    echo "0. Назад"
    read -rp "Выбор: " c

    case $c in
        1)
            apply_rule IN 22 tcp
            apply_rule IN 80 tcp
            apply_rule IN 443 tcp
            ;;
        2)
            while IFS=":" read -r name dir port proto; do
                apply_rule "$dir" "$port" "$proto"
            done < "$RULES_FILE"
            ;;
        3)
            read -rp "Имя: " name
            read -rp "Направление (IN/OUT/BOTH): " dir
            validate_direction "$dir" || return
            read -rp "Порт: " port
            validate_port "$port" || return
            read -rp "Протокол (tcp/udp/both): " proto
            validate_protocol "$proto" || return
            apply_rule "$dir" "$port" "$proto"
            ;;
    esac
    pause
}

delete_rules_menu() {
    clear
    echo "➖ Удаление"
    echo "1. Типовые (HTTP, HTTPS)"
    echo "2. Из rules.config"
    echo "3. По номеру (SSH защищён)"
    echo "0. Назад"
    read -rp "Выбор: " c

    case $c in
        1)
            delete_rule IN 80 tcp
            delete_rule IN 443 tcp
            ;;
        2)
            while IFS=":" read -r name dir port proto; do
                delete_rule "$dir" "$port" "$proto"
            done < "$RULES_FILE"
            ;;
        3)
            ufw status numbered
            read -rp "Номер: " num
            rule=$(ufw status numbered | sed -n "${num}p")
            echo "$rule" | grep -q "22/tcp" && \
                echo "❌ SSH удалять нельзя" || ufw delete "$num"
            ;;
    esac
    pause
}

edit_rules_file_menu() {
    clear
    echo "✏️ rules.config"
    echo "1. Показать"
    echo "2. Добавить"
    echo "3. Удалить"
    echo "0. Назад"
    read -rp "Выбор: " c

    case $c in
        1) nl -w2 -s'. ' "$RULES_FILE" ;;
        2)
            read -rp "Имя: " name
            read -rp "Направление: " dir
            validate_direction "$dir" || return
            read -rp "Порт: " port
            validate_port "$port" || return
            read -rp "Протокол: " proto
            validate_protocol "$proto" || return

            if config_rule_exists "$dir" "$port" "$proto"; then
                echo "⚠️ Дубликат"
            else
                echo "$name:$dir:$port:$proto" >> "$RULES_FILE"
            fi
            ;;
        3)
            nl -w2 -s'. ' "$RULES_FILE"
            read -rp "Строка: " line
            sed -i "${line}d" "$RULES_FILE"
            ;;
    esac
    pause
}

main_menu() {
    while true; do
        clear
        echo "🔥 UFW Manager"
        echo "1. Проверка"
        echo "2. Добавление"
        echo "3. Удаление"
        echo "4. rules.config"
        echo "0. Выход"
        read -rp "Выбор: " c

        case $c in
            1) check_rules_menu ;;
            2) add_rules_menu ;;
            3) delete_rules_menu ;;
            4) edit_rules_file_menu ;;
            0) exit 0 ;;
        esac
    done
}

# ---------- Старт ----------
check_root
init_rules_file
main_menu
