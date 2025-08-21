#!/bin/bash

# ==================== КОНФИГУРАЦИЯ ====================
NETWORK="192.168.1.0/24"
INTERFACE="eth0"
SCAN_DELAY="1s"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
LOG_DIR="/tmp/printer_audit"
SUSPECT_FILE="${LOG_DIR}/suspicious_activity_${TIMESTAMP}.log"
ALIVE_HOSTS="${LOG_DIR}/alive_hosts_${TIMESTAMP}.txt"
PRINT_HOSTS="${LOG_DIR}/print_hosts_${TIMESTAMP}.txt"
DETAILED_SCAN="${LOG_DIR}/detailed_scan_${TIMESTAMP}"

PRINTER_BRANDS="HP|Canon|Xerox|RICOH|KYOCERA|Epson|Brother|Lexmark|Konica|Minolta|OKI|Samsung|Sharp|Toshiba"
BLACKLIST_BRANDS="Unknown|Generic|Fake"

# ==================== НАСТРОЙКА БЕЗОПАСНОСТИ ====================
set -euo pipefail
export LANG=C.UTF-8

# ==================== ФУНКЦИИ ====================
log_suspicious() {
    local message=$1
    local ip=$2
    local details=$3
    
    echo "🚨 ПОДОЗРИТЕЛЬНАЯ АКТИВНОСТЬ: $message" | tee -a "$SUSPECT_FILE"
    echo "   📍 IP: $ip" | tee -a "$SUSPECT_FILE"
    echo "   📝 Детали: $details" | tee -a "$SUSPECT_FILE"
    echo "   ⏰ Время: $(date)" | tee -a "$SUSPECT_FILE"
    echo "----------------------------------------" | tee -a "$SUSPECT_FILE"
}

# Улучшенная функция выполнения команд с обработкой ошибок
run_nmap_scan() {
    local command="$1"
    local description="$2"
    local output_file="$3"
    local max_retries="${4:-3}"
    local retry_delay="${5:-10}"
    
    local attempt=1
    local success=false
    
    echo "   🔧 Выполняем: $description"
    
    while [ $attempt -le $max_retries ]; do
        if [ $attempt -gt 1 ]; then
            echo "   🔄 Попытка $attempt/$max_retries (через ${retry_delay}сек)..."
            sleep $retry_delay
        fi
        
        if eval "$command" 2>/dev/null; then
            success=true
            break
        else
            echo "   ⚠️  Ошибка при выполнении (попытка $attempt/$max_retries)"
            attempt=$((attempt + 1))
        fi
    done
    
    if [ "$success" = false ]; then
        echo "❌ КРИТИЧЕСКАЯ ОШИБКА: Не удалось выполнить: $description после $max_retries попыток"
        return 1
    fi
    
    # Проверяем, что файл создан и не пустой
    if [ ! -f "$output_file" ] || [ ! -s "$output_file" ]; then
        echo "⚠️  Предупреждение: Файл $output_file пуст или не создан"
        return 2
    fi
    
    return 0
}

# Функция безопасного извлечения IP
extract_ips_safe() {
    local input_file="$1"
    local output_file="$2"
    
    if [ ! -f "$input_file" ]; then
        echo "⚠️  Файл $input_file не существует"
        return 1
    fi
    
    grep "Up" "$input_file" 2>/dev/null | awk '{print $2}' > "$output_file" 2>/dev/null || {
        echo "⚠️  Ошибка при извлечении IP из $input_file"
        return 1
    }
    
    if [ ! -s "$output_file" ]; then
        echo "ℹ️  Нет данных для извлечения в $input_file"
        return 2
    fi
    
    return 0
}

# ==================== ПРОВЕРКИ ПЕРЕД ЗАПУСКОМ ====================
echo "🔍 [ЗАПУСК АУДИТА ПРИНТЕРОВ]"
echo "⏰ Время: $(date)"
echo "📁 Логи будут здесь: $LOG_DIR"
echo "🔧 Белый список брендов: $PRINTER_BRANDS"

if [ -n "$BLACKLIST_BRANDS" ]; then
    echo "⚫ Черный список брендов: $BLACKLIST_BRANDS"
fi

echo "=========================================================="

# Проверяем nmap
if ! command -v nmap >/dev/null 2>&1; then
    echo "❌ ОШИБКА: Nmap не установлен!"
    echo "💻 Установи его: sudo apt install nmap"
    exit 1
fi

# Проверяем netcat
if ! command -v nc >/dev/null 2>&1; then
    echo "❌ ОШИБКА: Netcat (nc) не установлен!"
    echo "💻 Установи его: sudo apt install netcat"
    exit 1
fi

# Проверяем права
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

# Инициализируем файл подозрительной активности
touch "$SUSPECT_FILE" || {
    echo "❌ Не могу создать файл: $SUSPECT_FILE"
    exit 1
}

# ==================== ШАГ 1: ПОИСК ЖИВЫХ УСТРОЙСТВ ====================
echo "📡 ШАГ 1: Ищем все устройства в сети..."
echo "   Сеть: $NETWORK"
echo "   Это займет 1-2 минуты..."

nmap_cmd="nmap -sn -T4 --max-retries 1 --host-timeout 30s \"$NETWORK\" -oG \"$ALIVE_HOSTS\""
if ! run_nmap_scan "$nmap_cmd" "Сканирование сети" "$ALIVE_HOSTS" 3 15; then
    echo "❌ Не удалось выполнить сканирование сети. Пропускаем этап."
    # Создаем пустой файл для продолжения работы
    touch "${ALIVE_HOSTS}.ips"
else
    # Извлекаем IP адреса
    if ! extract_ips_safe "$ALIVE_HOSTS" "${ALIVE_HOSTS}.ips"; then
        echo "⚠️  Не удалось извлечь IP адреса. Продолжаем с пустым списком."
        touch "${ALIVE_HOSTS}.ips"
    fi
fi

# Проверяем, есть ли живые устройства
if [ ! -s "${ALIVE_HOSTS}.ips" ]; then
    echo "😴 В сети нет активных устройств. Завершаем."
    exit 0
fi

LIVE_COUNT=$(wc -l < "${ALIVE_HOSTS}.ips" 2>/dev/null || echo "0")
echo "✅ Найдено устройств: $LIVE_COUNT"

# ==================== ШАГ 2: ПОИСК ПОРТОВ ПРИНТЕРОВ ====================
echo "🖨️  ШАГ 2: Ищем принтеры (порты 9100, 515, 631)..."
echo "   Сканируем $LIVE_COUNT устройств..."

nmap_cmd="nmap -p 9100,515,631 --open --max-retries 1 --host-timeout 30s -T4 -iL \"${ALIVE_HOSTS}.ips\" -oG \"$PRINT_HOSTS\""
if ! run_nmap_scan "$nmap_cmd" "Сканирование портов принтеров" "$PRINT_HOSTS" 3 15; then
    echo "❌ Не удалось выполнить сканирование портов. Пропускаем этап."
    touch "${PRINT_HOSTS}.ips"
else
    # Сохраняем IP адреса
    grep "open" "$PRINT_HOSTS" 2>/dev/null | awk '{print $2}' > "${PRINT_HOSTS}.ips" 2>/dev/null || {
        echo "⚠️  Ошибка при обработке результатов сканирования портов"
        touch "${PRINT_HOSTS}.ips"
    }
fi

# Считаем найденные принтеры
PRINT_COUNT=$(grep -c "open" "$PRINT_HOSTS" 2>/dev/null || echo "0")
echo "✅ Найдено устройств с портами принтеров: $PRINT_COUNT"

# ==================== ШАГ 3: ПРОВЕРКА ПОДОЗРИТЕЛЬНЫХ УСТРОЙСТВ ====================
if [ -s "${PRINT_HOSTS}.ips" ]; then
    echo "🔍 ШАГ 3: Проверяем найденные устройства..."
    echo "   ⚠️  Внимание: это займет 3-10 минут!"
    echo "   Сканируем $PRINT_COUNT устройств..."
    
    # Глубокое сканирование
    nmap_cmd="nmap -O -sV -T4 --osscan-guess --max-retries 1 --host-timeout 2m --script=\"ipp-enum,printer-info,smb2-security-mode\" -iL \"${PRINT_HOSTS}.ips\" -oA \"$DETAILED_SCAN\""
    if ! run_nmap_scan "$nmap_cmd" "Глубокое сканирование" "${DETAILED_SCAN}.nmap" 2 30; then
        echo "⚠️  Не удалось выполнить глубокое сканирование. Продолжаем анализ доступных данных."
    fi
    
    # Проверяем каждое устройство
    while IFS= read -r TARGET_IP; do
        [ -z "$TARGET_IP" ] && continue
        
        echo "   🔎 Проверяем: $TARGET_IP"
        
        # Безопасное извлечение информации из nmap
        OS_INFO="Не определена"
        SERVICE_INFO="Нет информации"
        SCRIPT_INFO="Нет данных"
        
        if [ -f "${DETAILED_SCAN}.nmap" ]; then
            OS_INFO=$(grep -A 15 "Nmap scan report for $TARGET_IP" "${DETAILED_SCAN}.nmap" 2>/dev/null | \
                     grep -E "Running|OS details|Aggressive OS guesses" | head -3 || echo "Не определена")
            
            SERVICE_INFO=$(grep -A 20 "Nmap scan report for $TARGET_IP" "${DETAILED_SCAN}.nmap" 2>/dev/null | \
                          grep -E "9100|515|631|445|135" | grep -E "open|filtered" || echo "Нет информации")
            
            SCRIPT_INFO=$(grep -A 10 -B 2 "$TARGET_IP" "${DETAILED_SCAN}.nmap" 2>/dev/null | \
                         grep -E "printer-info|ipp-enum|message_signing" | head -5 || echo "Нет данных")
        fi
        
        # Проверяем признаки взлома
        SUSPICIOUS=false
        REASONS=()
        
        # 1. Проверка ОС на портах принтера
        if echo "$OS_INFO" | grep -qi "Windows\|Linux\|Mac\|macOS\|Apple\|Darwin" && \
           echo "$SERVICE_INFO" | grep -q "9100/open\|631/open"; then
            SUSPICIOUS=true
            REASONS+=("Компьютер выдает себя за принтер")
        fi
        
        # 2. Проверка SMB подписи
        if echo "$SCRIPT_INFO" | grep -q "message_signing: disabled"; then
            SUSPICIOUS=true
            REASONS+=("SMB подпись отключена - уязвимость")
        fi
        
        # 3. Проверка Windows служб
        if echo "$SERVICE_INFO" | grep -q "445/open.*microsoft-ds\|135/open.*msrpc"; then
            SUSPICIOUS=true
            REASONS+=("Найден Windows-сервер вместо принтера")
        fi
        
        # 4. Проверка по белым и черным спискам
        if echo "$SCRIPT_INFO" | grep -q "printer-info"; then
            if ! echo "$SCRIPT_INFO" | grep -qi "$PRINTER_BRANDS"; then
                SUSPICIOUS=true
                REASONS+=("Устройство не из белого списка брендов")
            fi
            
            if echo "$SCRIPT_INFO" | grep -qi "$BLACKLIST_BRANDS"; then
                SUSPICIOUS=true
                REASONS+=("Обнаружен бренд из черного списка")
            fi
        fi
        
        # 5. PJL-верификация
        if [ "$SUSPICIOUS" = true ] && echo "$SERVICE_INFO" | grep -q "9100/open"; then
            echo "      🔬 Проверяем подлинность через PJL..."
            log_suspicious "PJL_VERIFICATION_START" "$TARGET_IP" "Начало PJL-верификации"
            
            PJL_RESPONSE=""
            for attempt in {1..3}; do
                if [ $attempt -gt 1 ]; then
                    echo "      🔄 Повторная попытка PJL ($attempt/3)..."
                    sleep 2
                fi
                
                PJL_RESPONSE=$(timeout 5 echo "@PJL INFO ID" | nc -w 3 "$TARGET_IP" 9100 2>/dev/null | tr -d '\0' | head -1 || true)
                
                if [ -n "$PJL_RESPONSE" ]; then
                    break
                fi
            done
            
            log_suspicious "PJL_VERIFICATION_ATTEMPT" "$TARGET_IP" "Отправлена команда: @PJL INFO ID"
            
            if [[ -n "$PJL_RESPONSE" ]]; then
                echo "      📨 Получен ответ: $PJL_RESPONSE"
                log_suspicious "PJL_RESPONSE_RECEIVED" "$TARGET_IP" "Получен ответ: $PJL_RESPONSE"
                
                if echo "$PJL_RESPONSE" | grep -qi "PJL\|@PJL\|HP\|Canon\|Xerox\|Epson\|Brother"; then
                    echo "      ✅ PJL Check: Устройство ответило как настоящий принтер."
                    log_suspicious "PJL_VERIFICATION_PASSED" "$TARGET_IP" "Устройство ответило как принтер: $PJL_RESPONSE"
                    SUSPICIOUS=false
                    REASONS=("Обнаружены признаки принтера (PJL ответ: $PJL_RESPONSE)")
                else
                    echo "      ⚠️ PJL Check: Получен нестандартный ответ."
                    log_suspicious "PJL_VERIFICATION_FAILED" "$TARGET_IP" "Нестандартный ответ PJL: $PJL_RESPONSE"
                    REASONS+=("Не прошел PJL-верификацию. Ответ: $PJL_RESPONSE")
                fi
            else
                echo "      ❗ PJL Check: Устройство не ответило на PJL-запрос."
                log_suspicious "PJL_VERIFICATION_TIMEOUT" "$TARGET_IP" "Устройство не ответило на PJL INFO ID"
                REASONS+=("Не ответил на PJL INFO ID")
            fi
        fi
        
        # Финализация проверки
        if [ "$SUSPICIOUS" = true ]; then
            REASON_STR=$(IFS='; '; echo "${REASONS[*]}")
            log_suspicious "ВОЗМОЖНА ПОДМЕНА ПРИНТЕРА" "$TARGET_IP" "$REASON_STR"
            echo "      ❗ ВНИМАНИЕ: Обнаружена угроза!"
            echo "      🖥️  OS: $OS_INFO"
            echo "      🛠️  Services: $SERVICE_INFO"
            echo "      📊 Scripts: $SCRIPT_INFO"
        else
            echo "      ✅ Устройство в порядке"
            log_suspicious "DEVICE_VERIFIED" "$TARGET_IP" "Устройство верифицировано как принтер"
        fi
        
    done < "${PRINT_HOSTS}.ips"
else
    echo "ℹ️  Нет устройств с открытыми портами принтеров для проверки."
fi

# ==================== ШАГ 4: ПРОВЕРКА СЕТЕВЫХ ПРОТОКОЛОВ ====================
echo ""
read -p "❓ Проверить сеть на уязвимости LLMNR/NBNS? (y/N): " -n 1 -r
echo

if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo "📡 ШАГ 4: Проверка сетевых протоколов (60 секунд)..."
    
    BROADCAST_CHECK=""
    if command -v timeout >/dev/null 2>&1; then
        BROADCAST_CHECK=$(timeout 60 nmap --script broadcast-llmnr-discover,broadcast-nbns-discover -e "$INTERFACE" 2>/dev/null || true)
    else
        echo "⚠️  Утилита timeout не найдена, сканирование может затянуться"
        BROADCAST_CHECK=$(nmap --script broadcast-llmnr-discover,broadcast-nbns-discover -e "$INTERFACE" 2>/dev/null | head -50 || true)
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
    SUSPECT_COUNT=$(grep -c "ПОДОЗРИТЕЛЬНАЯ АКТИВНОСТЬ" "$SUSPECT_FILE" 2>/dev/null || echo "0")
    echo "🚨 НАЙДЕНО УГРОЗ: $SUSPECT_COUNT"
    echo "📄 Подробности в файле: $SUSPECT_FILE"
    echo ""
    echo "⚡ РЕКОМЕНДАЦИИ:"
    echo "   1. Проверьте IP адреса из отчета"
    echo "   2. Изолируйте подозрительные устройства от сети"
    echo "   3. Проверьте логи на этих устройствах"
    echo "   4. 🔧 Обновите белый список брендов если нужно"
else
    echo "✅ УГРОЗ не обнаружено! Сеть защищена."
fi

echo ""
echo "📊 Все файлы сканирования: $LOG_DIR"

if [ -f "${DETAILED_SCAN}.nmap" ]; then
    echo "🔍 Основной файл с деталями: ${DETAILED_SCAN}.nmap"
fi

echo "🔧 Белый список брендов: $PRINTER_BRANDS"

if [ -n "$BLACKLIST_BRANDS" ]; then
    echo "⚫ Черный список брендов: $BLACKLIST_BRANDS"
fi

echo "💡 Чтобы изменить списки, отредактируйте переменные PRINTER_BRANDS и BLACKLIST_BRANDS"
echo "=========================================================="

# Копируем логи
if [ -f "$SUSPECT_FILE" ] && [ -s "$SUSPECT_FILE" ]; then
    cp "$SUSPECT_FILE" "/tmp/last_printer_audit.log" 2>/dev/null || true
    echo "📋 Краткий отчет также сохранен: /tmp/last_printer_audit.log"
fi

echo "✅ Скрипт завершил работу успешно"
exit 0
