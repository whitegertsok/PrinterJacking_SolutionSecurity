#!/bin/bash

# ==================== КОНФИГУРАЦИЯ ====================
# Настройки под свою сеть 
NETWORK="192.168.1.0/24"          # Твоя сеть (например: 192.168.0.0/24)
INTERFACE="eth0"                  # Твой сетевой интерфейс (проверь: ip a)
SCAN_DELAY="1s"                   # Задержка между запросами (чтобы не сломать сеть)
TIMESTAMP=$(date +%Y%m%d_%H%M%S)  # Текущее время для имен файлов
LOG_DIR="/tmp/printer_audit"       # Папка для логов (можно поменять на /var/log/)
SUSPECT_FILE="${LOG_DIR}/suspicious_activity_${TIMESTAMP}.log"
ALIVE_HOSTS="${LOG_DIR}/alive_hosts_${TIMESTAMP}.txt"
PRINT_HOSTS="${LOG_DIR}/print_hosts_${TIMESTAMP}.txt"
DETAILED_SCAN="${LOG_DIR}/detailed_scan_${TIMESTAMP}"

# ==================== БЕЛЫЙ СПИСОК БРЕНДОВ ПРИНТЕРОВ ====================
# 🔧 НАСТРОЙКА: Добавляй сюда ВСЕ бренды принтеров, которые есть в сканируемой сети
# 📝 Формат: "HP|Canon|Xerox|Epson" - через | без пробелов
# 💡 Пример: "HP|Canon|Xerox|RICOH|KYOCERA|Epson|Brother|Lexmark"
PRINTER_BRANDS="HP|Canon|Xerox|RICOH|KYOCERA|Epson|Brother|Lexmark|Konica|Minolta|OKI|Samsung|Sharp|Toshiba"

# ==================== ЧЕРНЫЙ СПИСОК (ОПЦИОНАЛЬНО) ====================
# ⚠️ Исключить определенные бренды, добавь их сюда
# ❗ Пример: "Unknown|Generic|Fake" - устройства с такими брендами будут подозрительными
BLACKLIST_BRANDS="Unknown|Generic|Fake"

# ==================== НАСТРОЙКА БЕЗОПАСНОСТИ ====================
set -euo pipefail  # Автоматически останавливаем скрипт при ошибках
export LANG=C.UTF-8  # Правильная кодировка для русских букв

# ==================== ПРОВЕРКИ ПЕРЕД ЗАПУСКОМ ====================
echo "🔍 [ЗАПУСК АУДИТА ПРИНТЕРОВ]"
echo "⏰ Время: $(date)"
echo "📁 Логи будут здесь: $LOG_DIR"
echo "🔧 Белый список брендов: $PRINTER_BRANDS"
if [ -n "$BLACKLIST_BRANDS" ]; then
    echo "⚫ Черный список брендов: $BLACKLIST_BRANDS"
fi
echo "=========================================================="

# Проверяем, установлен ли nmap
if ! command -v nmap >/dev/null 2>&1; then
    echo "❌ ОШИБКА: Nmap не установлен!"
    echo "💻 Установи его: sudo apt install nmap"
    exit 1
fi

# Проверяем права (нужны root для некоторых сканирований)
if [ "$EUID" -ne 0 ]; then
    echo "⚠️  Предупреждение: Скрипт запущен без root прав"
    echo "   Некоторые проверки могут не работать"
    sleep 2
fi

# Создаем папку для логов
mkdir -p "$LOG_DIR" || {
    echo "❌ Не могу создать папку: $LOG_DIR"
    exit 1
}

# ==================== ФУНКЦИИ ====================
# Функция для записи подозрительных событий
log_suspicious() {
    local message=$1    # Что случилось
    local ip=$2         # IP адрес
    local details=$3    # Подробности
    
    echo "🚨 ПОДОЗРИТЕЛЬНАЯ АКТИВНОСТЬ: $message" | tee -a "$SUSPECT_FILE"
    echo "   📍 IP: $ip" | tee -a "$SUSPECT_FILE"
    echo "   📝 Детали: $details" | tee -a "$SUSPECT_FILE"
    echo "   ⏰ Время: $(date)" | tee -a "$SUSPECT_FILE"
    echo "----------------------------------------" | tee -a "$SUSPECT_FILE"
}

# ==================== ШАГ 1: ПОИСК ЖИВЫХ УСТРОЙСТВ ====================
echo "📡 ШАГ 1: Ищем все устройства в сети..."
echo "   Сеть: $NETWORK"
echo "   Это займет 1-2 минуты..."

if ! nmap -sn -T4 --max-retries 1 --host-timeout 30s "$NETWORK" -oG "$ALIVE_HOSTS" > /dev/null 2>&1; then
    echo "❌ Ошибка сканирования сети!"
    exit 1
fi

# Извлекаем только IP адреса живых устройств
grep "Up" "$ALIVE_HOSTS" | awk '{print $2}' > "${ALIVE_HOSTS}.ips"

# Проверяем, есть ли живые устройства
if [ ! -s "${ALIVE_HOSTS}.ips" ]; then
    echo "😴 В сети нет активных устройств. Завершаем."
    exit 0
fi

LIVE_COUNT=$(wc -l < "${ALIVE_HOSTS}.ips")
echo "✅ Найдено устройств: $LIVE_COUNT"

# ==================== ШАГ 2: ПОИСК ПОРТОВ ПРИНТЕРОВ ====================
echo "🖨️  ШАГ 2: Ищем принтеры (порты 9100, 515, 631)..."
echo "   Сканируем $LIVE_COUNT устройств..."

if ! nmap -p 9100,515,631 --open --max-retries 1 --host-timeout 30s -T4 \
    -iL "${ALIVE_HOSTS}.ips" -oG "$PRINT_HOSTS" > /dev/null 2>&1; then
    echo "❌ Ошибка сканирования портов!"
    exit 1
fi

# Считаем найденные принтеры
PRINT_COUNT=$(grep -c "open" "$PRINT_HOSTS" || true)
echo "✅ Найдено устройств с портами принтеров: $PRINT_COUNT"

# Сохраняем IP адреса подозрительных устройств
grep "open" "$PRINT_HOSTS" | awk '{print $2}' > "${PRINT_HOSTS}.ips"

# ==================== ШАГ 3: ПРОВЕРКА ПОДОЗРИТЕЛЬНЫХ УСТРОЙСТВ ====================
if [ -s "${PRINT_HOSTS}.ips" ]; then
    echo "🔍 ШАГ 3: Проверяем найденные устройства..."
    echo "   ⚠️  Внимание: это займет 3-10 минут!"
    echo "   Сканируем $PRINT_COUNT устройств..."
    
    # Глубокое сканирование каждого подозрительного устройства
    if ! nmap -O -sV -T4 --osscan-guess --max-retries 1 --host-timeout 2m \
        --script="ipp-enum,printer-info,smb2-security-mode" \
        -iL "${PRINT_HOSTS}.ips" -oA "$DETAILED_SCAN" > /dev/null 2>&1; then
        echo "⚠️  Были ошибки при сканировании, но продолжаем..."
    fi
    
    # Проверяем каждое устройство
    while IFS= read -r TARGET_IP; do
        echo "   🔎 Проверяем: $TARGET_IP"
        
        # Достаем информацию из результатов nmap
        OS_INFO=$(grep -A 15 "Nmap scan report for $TARGET_IP" "${DETAILED_SCAN}.nmap" 2>/dev/null | \
                 grep -E "Running|OS details|Aggressive OS guesses" | head -3 || echo "Не определена")
        
        SERVICE_INFO=$(grep -A 20 "Nmap scan report for $TARGET_IP" "${DETAILED_SCAN}.nmap" 2>/dev/null | \
                      grep -E "9100|515|631|445|135" | grep -E "open|filtered" || echo "Нет информации")
        
        SCRIPT_INFO=$(grep -A 10 -B 2 "$TARGET_IP" "${DETAILED_SCAN}.nmap" 2>/dev/null | \
                     grep -E "printer-info|ipp-enum|message_signing" | head -5 || echo "Нет данных")
        
        # ===== ПРОВЕРЯЕМ ПРИЗНАКИ ВЗЛОМА =====
        SUSPICIOUS=false
        REASONS=()
        
        # 1. Windows\|Linux\|Mac\|macOS\|Apple\|Darwin на портах принтера - ГЛАВНЫЙ ПРИЗНАК!
        if echo "$OS_INFO" | grep -qi "Windows\|Linux\|Mac\|macOS\|Apple\|Darwin" && \
           echo "$SERVICE_INFO" | grep -q "9100/open\|631/open"; then
            SUSPICIOUS=true
            REASONS+=("Компьютер выдает себя за принтер")
        fi
        
        # 2. Отключена SMB подпись - уязвимость для атак
        if echo "$SCRIPT_INFO" | grep -q "message_signing: disabled"; then
            SUSPICIOUS=true
            REASONS+=("SMB подпись отключена - уязвимость")
        fi
        
        # 3. Windows службы на "принтере"
        if echo "$SERVICE_INFO" | grep -q "445/open.*microsoft-ds\|135/open.*msrpc"; then
            SUSPICIOUS=true
            REASONS+=("Найден Windows-сервер вместо принтера")
        fi
        
        # 4. 🔧 ПРОВЕРКА ПО БЕЛОМУ И ЧЕРНОМУ СПИСКАМ БРЕНДОВ
        # 📝 Логика: Если есть информация о принтере, но нет известных брендов ИЛИ есть запрещенные бренды
        if echo "$SCRIPT_INFO" | grep -q "printer-info"; then
            # 🟢 Проверка белого списка: если бренд НЕ в белом списке
            if ! echo "$SCRIPT_INFO" | grep -qi "$PRINTER_BRANDS"; then
                SUSPICIOUS=true
                REASONS+=("Устройство не из белого списка брендов")
            fi
            
            # 🔴 Проверка черного списка: если бренд в черном списке
            if echo "$SCRIPT_INFO" | grep -qi "$BLACKLIST_BRANDS"; then
                SUSPICIOUS=true
                REASONS+=("Обнаружен бренд из черного списка")
            fi
        fi
        
        # ===== ДЕЙСТВИЯ ЕСЛИ НАШЛИ ПОДОЗРИТЕЛЬНОЕ УСТРОЙСТВО =====
        if [ "$SUSPICIOUS" = true ]; then
            REASON_STR=$(IFS='; '; echo "${REASONS[*]}")
            log_suspicious "ВОЗМОЖНА ПОДМЕНА ПРИНТЕРА" "$TARGET_IP" "$REASON_STR"
            echo "      ❗ ВНИМАНИЕ: Обнаружена угроза!"
            echo "      🖥️  OS: $OS_INFO"
            echo "      🛠️  Services: $SERVICE_INFO"
            echo "      📊 Scripts: $SCRIPT_INFO"
        else
            echo "      ✅ Устройство в порядке (настоящий принтер)"
        fi
        
    done < "${PRINT_HOSTS}.ips"
else
    echo "✅ Подозрительных принтеров не найдено"
fi

# ==================== ШАГ 4: ПРОВЕРКА СЕТЕВЫХ ПРОТОКОЛОВ ====================
echo ""
read -p "❓ Проверить сеть на уязвимости LLMNR/NBNS? (y/N): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo "📡 ШАГ 4: Проверка сетевых протоколов (60 секунд)..."
    
    if command -v timeout >/dev/null 2>&1; then
        BROADCAST_CHECK=$(timeout 60 nmap --script broadcast-llmnr-discover,broadcast-nbns-discover -e "$INTERFACE" 2>&1 || true)
    else
        echo "⚠️  Утилита timeout не найдена, сканирование может затянуться"
        BROADCAST_CHECK=$(nmap --script broadcast-llmnr-discover,broadcast-nbns-discover -e "$INTERFACE" 2>&1 | head -50 || true)
    fi
    
    if echo "$BROADCAST_CHECK" | grep -q "discovered"; then
        echo "⚠️  Обнаружена сетевая активность LLMNR/NBNS"
        echo "$BROADCAST_CHECK" | grep "discovered" | while read -r line; do
            log_suspicious "СЕТЕВАЯ АКТИВНОСТЬ" "N/A" "$line"
        done
    else
        echo "✅ Сетевые протоколы в порядке"
    fi
fi

# ==================== ФИНАЛЬНЫЙ ОТЧЕТ ====================
echo ""
echo "=========================================================="
echo "🎉 АУДИТ ЗАВЕРШЕН: $(date)"
echo "=========================================================="

if [ -f "$SUSPECT_FILE" ] && [ -s "$SUSPECT_FILE" ]; then
    SUSPECT_COUNT=$(grep -c "ПОДОЗРИТЕЛЬНАЯ АКТИВНОСТЬ" "$SUSPECT_FILE")
    echo "🚨 НАЙДЕНО УГРОЗ: $SUSPECT_COUNT"
    echo "📄 Подробности в файле: $SUSPECT_FILE"
    echo ""
    echo "⚡ РЕКОМЕНДАЦИИ:"
    echo "   1. Проверьте IP адреса из отчета"
    echo "   2. Изолируйте подозрительные устройства от сети"
    echo "   3. Проверьте логи на этих устройствах"
    echo "   4. 🔧 Обновите белый список брендов если нужно"
else
    echo "✅ УГРОЗ не обнаруженно! Сеть защищена."
fi

echo ""
echo "📊 все файлы сканирования: $LOG_DIR"
echo "🔍 Основной файл с деталями: ${DETAILED_SCAN}.nmap"
echo "🔧 Белый список брендов: $PRINTER_BRANDS"
if [ -n "$BLACKLIST_BRANDS" ]; then
    echo "⚫ Черный список брендов: $BLACKLIST_BRANDS"
fi
echo "💡 Чтобы изменить списки, отредактируйте переменные PRINTER_BRANDS и BLACKLIST_BRANDS"
echo "=========================================================="

# Копируем логи в удобное место
cp "$SUSPECT_FILE" "/tmp/last_printer_audit.log" 2>/dev/null || true
echo "📋 Краткий отчет также сохранен: /tmp/last_printer_audit.log"
