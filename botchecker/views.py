# БЛОК 1: ИМПОРТ БИБЛИОТЕК
import re                        # Регулярные выражения для проверки формата IP-адресов
import random                    # Генерация случайных параметров для добавляемых IP
import io                        # Работа с потоками данных (для экспорта в Excel)
import csv                       # Запись данных в CSV-формат
import xlsxwriter                # Создание Excel-файлов
from django.shortcuts import render, redirect  # Рендеринг шаблонов и перенаправление
from django.http import HttpResponse          # Отправка файлов (CSV, Excel)
from django.views.decorators.csrf import csrf_exempt  # Отключение CSRF для POST-запросов
from django.utils import timezone              # Работа со временем (не используется в данном фрагменте)

# БЛОК 2: КОНСТАНТЫ ДАННЫХ

# Чёрный список C&C серверов (6 IP-адресов, считающихся опасными)
C2_SERVERS = ["185.130.5.253", "94.23.15.12", "193.42.4.1",
              "176.9.75.45", "89.45.87.12", "5.188.86.45"]

# Начальные данные: 10 IP-адресов с фиксированными параметрами
# Формат: (IP, соединения, подозр.порт, подозр.процесс, высокий трафик, C&C, ночная активность)
INITIAL_IPS = [
    ("185.130.5.253", 250, 1, 1, 1, 1, 1),  # C&C сервер, много соединений
    ("8.8.8.8", 45, 0, 0, 0, 0, 1),         # Безопасный DNS
    ("94.23.15.12", 180, 1, 1, 0, 1, 0),
    ("1.1.1.1", 30, 0, 0, 0, 0, 1),
    ("193.42.4.1", 500, 1, 1, 1, 1, 1),
    ("176.9.75.45", 15, 0, 0, 0, 1, 0),
    ("8.8.4.4", 75, 0, 0, 0, 0, 1),
    ("89.45.87.12", 320, 1, 1, 1, 1, 0),
    ("5.188.86.45", 150, 1, 0, 1, 1, 1),
    ("208.67.222.222", 60, 0, 0, 0, 0, 1)
]

# БЛОК 3: ФУНКЦИЯ РАСЧЁТА УГРОЗЫ

def calculate_threat(connections, suspicious_port, unknown_process, high_traffic, c2, night_activity):
    """
    Расчёт уровня угрозы и принятие решения BLOCK/ALLOW
    Веса факторов: соединения>100 (+1), подозр.порт (+1), подозр.процесс (+2),
                  высокий трафик (+1), C&C сервер (+3), ночная активность (+1)
    Порог блокировки: 3 балла
    """
    threat = 0                                                    # Начальное значение угрозы

    # Фактор 1: много соединений (>100) → +1 балл
    if connections > 100: threat += 1
    # Фактор 2: подозрительный порт → +1 балл
    if suspicious_port == 1: threat += 1
    # Фактор 3: подозрительный процесс → +2 балла (более опасный)
    if unknown_process == 1: threat += 2
    # Фактор 4: высокий трафик → +1 балл
    if high_traffic == 1: threat += 1
    # Фактор 5: C&C сервер → +3 балла (наибольший вес)
    if c2 == 1: threat += 3
    # Фактор 6: ночная активность → +1 балл
    if night_activity == 1: threat += 1

    # Решение: если угроза ≥ 3 → BLOCK, иначе ALLOW
    decision = "BLOCK" if threat >= 3 else "ALLOW"
    return threat, decision

# БЛОК 4: СТРАНИЦА "О ПРОЕКТЕ"

def about(request):
    """Рендеринг статической страницы с описанием проекта"""
    return render(request, 'botchecker/about.html')


# БЛОК 5: СБРОС ТАБЛИЦЫ К НАЧАЛЬНОМУ СОСТОЯНИЮ

def reset_to_initial(request):
    """Восстановление таблицы до начальных 10 IP-адресов"""
    data = []                     # Список для хранения записей
    next_id = 1                   # Счётчик ID

    # Цикл по начальным 10 IP-адресам
    for ip, conn, sp, up, ht, c2, night in INITIAL_IPS:
        threat, decision = calculate_threat(conn, sp, up, ht, c2, night)  # Расчёт угрозы
        data.append({
            "id": next_id, "ip": ip, "connections": conn,
            "suspicious_port": sp, "unknown_process": up, "high_traffic": ht,
            "c2_server": c2, "night_activity": night,
            "threat_level": threat, "decision": decision
        })
        next_id += 1

    # Сохранение данных в сессии Django
    request.session['data'] = data
    request.session['next_id'] = next_id
    request.session['message'] = {"text": "Таблица сброшена до 10 исходных IP.", "type": "info"}
    request.session.modified = True  # Помечаем сессию как изменённую

# БЛОК 6: ГЛАВНАЯ СТРАНИЦА (ОБРАБОТКА ЗАПРОСОВ)

@csrf_exempt  # Отключаем CSRF для упрощения (в учебном проекте)
def index(request):
    """Главная страница: отображение таблицы, графиков, добавление IP, очистка"""

    # Инициализация данных, если сессия пуста
    if 'data' not in request.session:
        reset_to_initial(request)

    message = request.session.pop('message', None)  # Получение уведомления из сессии

    if request.method == 'POST':
        # Обработка кнопки "Сбросить"
        if 'clear' in request.POST:
            reset_to_initial(request)
            return redirect(request.path)

        ip_input = request.POST.get('ip', '').strip()
        bulk_ips = request.POST.get('bulk_ips', '').strip()
        added = False
        msg_text = None
        msg_type = "info"

        # --- ДОБАВЛЕНИЕ ОДНОГО IP ---
        if ip_input and re.match(r'^(\d{1,3}\.){3}\d{1,3}$', ip_input):
            # Валидация формата IP с помощью регулярного выражения

            # Проверка на уникальность
            exists = any(item['ip'] == ip_input for item in request.session['data'])
            if not exists:
                # Случайная генерация параметров для нового IP
                connections = random.randint(1, 250)
                suspicious_port = random.choice([0, 1])
                unknown_process = random.choice([0, 1])
                high_traffic = random.choice([0, 1])
                night_activity = random.choice([0, 1])
                c2 = 1 if random.random() < 0.33 else 0   # 33% вероятность быть C&C сервером

                threat, decision = calculate_threat(connections, suspicious_port, unknown_process, high_traffic, c2, night_activity)

                new_entry = {
                    "id": request.session['next_id'], "ip": ip_input,
                    "connections": connections, "suspicious_port": suspicious_port,
                    "unknown_process": unknown_process, "high_traffic": high_traffic,
                    "c2_server": c2, "night_activity": night_activity,
                    "threat_level": threat, "decision": decision
                }
                request.session['data'].append(new_entry)
                request.session['next_id'] += 1
                added = True
                msg_text = f"IP {ip_input} добавлен (C&C={'Да' if c2 else 'Нет'}, угроза={threat} → {decision})."
                msg_type = "danger" if decision == "BLOCK" else "success"
            else:
                msg_text = f"IP {ip_input} уже есть в таблице."
                msg_type = "warning"

        # --- МАССОВОЕ ДОБАВЛЕНИЕ IP ---
        elif bulk_ips:
            # Разделение строки по запятым, пробелам или переводам строк
            ips = re.split(r'[,\s\n]+', bulk_ips)
            added_count = 0
            for ip in ips:
                ip = ip.strip()
                if not ip or not re.match(r'^(\d{1,3}\.){3}\d{1,3}$', ip):
                    continue  # Пропускаем неверные IP
                if any(item['ip'] == ip for item in request.session['data']):
                    continue  # Пропускаем дубликаты

                # Случайная генерация параметров для нового IP
                connections = random.randint(1, 250)
                suspicious_port = random.choice([0, 1])
                unknown_process = random.choice([0, 1])
                high_traffic = random.choice([0, 1])
                night_activity = random.choice([0, 1])
                c2 = 1 if random.random() < 0.33 else 0

                threat, decision = calculate_threat(connections, suspicious_port, unknown_process, high_traffic, c2, night_activity)

                new_entry = {
                    "id": request.session['next_id'], "ip": ip,
                    "connections": connections, "suspicious_port": suspicious_port,
                    "unknown_process": unknown_process, "high_traffic": high_traffic,
                    "c2_server": c2, "night_activity": night_activity,
                    "threat_level": threat, "decision": decision
                }
                request.session['data'].append(new_entry)
                request.session['next_id'] += 1
                added_count += 1

            if added_count > 0:
                added = True
                msg_text = f"Добавлено {added_count} IP со случайными параметрами."
                msg_type = "info"
            else:
                msg_text = "Нет новых IP для добавления."
                msg_type = "warning"

        if added:
            request.session.modified = True
            request.session['message'] = {"text": msg_text, "type": msg_type}
            return redirect(request.path)  # Перенаправление для обновления страницы

    # Рендеринг главной страницы с данными из сессии
    context = {"data": request.session['data'], "message": message}
    return render(request, 'botchecker/index.html', context)

# БЛОК 7: СТРАНИЦА АНАЛИТИКИ

def analytics(request):
    """Страница аналитики: статистика, распределения, графики"""
    data = request.session.get('data', [])

    # Проверка наличия данных
    if not data:
        return render(request, 'botchecker/analytics.html', {
            'has_data': False,
            'message': 'Нет данных для анализа. Сначала добавьте IP-адреса на главной странице.'
        })

    total = len(data)

    # Подсчёт BLOCK и ALLOW
    block_count = sum(1 for row in data if row['decision'] == 'BLOCK')
    allow_count = total - block_count
    block_percent = round(block_count / total * 100, 1) if total > 0 else 0
    allow_percent = round(allow_count / total * 100, 1) if total > 0 else 0

    # Подсчёт C&C серверов
    c2_count = sum(1 for row in data if row['c2_server'] == 1)
    c2_percent = round(c2_count / total * 100, 1) if total > 0 else 0

    # Статистика по уровням угрозы
    threat_levels = [row['threat_level'] for row in data]
    avg_threat = round(sum(threat_levels) / total, 1) if total > 0 else 0
    max_threat = max(threat_levels) if threat_levels else 0
    min_threat = min(threat_levels) if threat_levels else 0

    # Распределение уровней угрозы (0–9 баллов)
    threat_distribution = {i: 0 for i in range(10)}
    for level in threat_levels:
        threat_distribution[level] = threat_distribution.get(level, 0) + 1

    context = {
        'has_data': True,
        'total': total,
        'block_count': block_count,
        'allow_count': allow_count,
        'block_percent': block_percent,
        'allow_percent': allow_percent,
        'c2_count': c2_count,
        'c2_percent': c2_percent,
        'avg_threat': avg_threat,
        'max_threat': max_threat,
        'min_threat': min_threat,
        'threat_distribution': threat_distribution,
        'data': data,
    }
    return render(request, 'botchecker/analytics.html', context)

# БЛОК 8: ЭКСПОРТ В EXCEL

def export_excel(request):
    """Экспорт таблицы результатов в Excel-файл (XLSX)"""
    data = request.session.get('data', [])
    if not data:
        return HttpResponse("Нет данных для экспорта", status=404)

    # Настройка HTTP-ответа для скачивания Excel-файла
    response = HttpResponse(content_type='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')
    response['Content-Disposition'] = 'attachment; filename="bot_analysis.xlsx"'

    output = io.BytesIO()
    workbook = xlsxwriter.Workbook(output)
    worksheet = workbook.add_worksheet('Результаты анализа')

    # Запись заголовков
    headers = ['ID', 'IP адрес', 'Соединений', 'Подозр. порт', 'Подозр. процесс',
               'Высокий трафик', 'C&C сервер', 'Ночная активность', 'Уровень угрозы', 'Решение']
    for col, header in enumerate(headers):
        worksheet.write(0, col, header)

    # Запись данных построчно
    for row_idx, row in enumerate(data, start=1):
        worksheet.write(row_idx, 0, row['id'])
        worksheet.write(row_idx, 1, row['ip'])
        worksheet.write(row_idx, 2, row['connections'])
        worksheet.write(row_idx, 3, row['suspicious_port'])
        worksheet.write(row_idx, 4, row['unknown_process'])
        worksheet.write(row_idx, 5, row['high_traffic'])
        worksheet.write(row_idx, 6, row['c2_server'])
        worksheet.write(row_idx, 7, row['night_activity'])
        worksheet.write(row_idx, 8, row['threat_level'])
        worksheet.write(row_idx, 9, row['decision'])

    workbook.close()
    response.write(output.getvalue())
    return response