import re
import random
import io
import csv
import xlsxwriter
from django.shortcuts import render, redirect
from django.http import HttpResponse
from django.views.decorators.csrf import csrf_exempt
from django.utils import timezone

# ---------- Константы для расчёта ----------
C2_SERVERS = ["185.130.5.253", "94.23.15.12", "193.42.4.1",
              "176.9.75.45", "89.45.87.12", "5.188.86.45"]

# Начальные данные (10 IP из контейнера)
INITIAL_IPS = [
    ("185.130.5.253", 250, 1, 1, 1, 1, 1),
    ("8.8.8.8", 45, 0, 0, 0, 0, 1),
    ("94.23.15.12", 180, 1, 1, 0, 1, 0),
    ("1.1.1.1", 30, 0, 0, 0, 0, 1),
    ("193.42.4.1", 500, 1, 1, 1, 1, 1),
    ("176.9.75.45", 15, 0, 0, 0, 1, 0),
    ("8.8.4.4", 75, 0, 0, 0, 0, 1),
    ("89.45.87.12", 320, 1, 1, 1, 1, 0),
    ("5.188.86.45", 150, 1, 0, 1, 1, 1),
    ("208.67.222.222", 60, 0, 0, 0, 0, 1)
]

def calculate_threat(connections, suspicious_port, unknown_process, high_traffic, c2, night_activity):
    threat = 0
    if connections > 100: threat += 1
    if suspicious_port == 1: threat += 1
    if unknown_process == 1: threat += 2
    if high_traffic == 1: threat += 1
    if c2 == 1: threat += 3
    if night_activity == 1: threat += 1
    decision = "BLOCK" if threat >= 3 else "ALLOW"
    return threat, decision

def about(request):
    return render(request, 'botchecker/about.html')

def reset_to_initial(request):
    data = []
    next_id = 1
    for ip, conn, sp, up, ht, c2, night in INITIAL_IPS:
        threat, decision = calculate_threat(conn, sp, up, ht, c2, night)
        data.append({
            "id": next_id, "ip": ip, "connections": conn,
            "suspicious_port": sp, "unknown_process": up, "high_traffic": ht,
            "c2_server": c2, "night_activity": night,
            "threat_level": threat, "decision": decision
        })
        next_id += 1
    request.session['data'] = data
    request.session['next_id'] = next_id
    request.session['message'] = {"text": "Таблица сброшена до 10 исходных IP.", "type": "info"}
    request.session.modified = True

@csrf_exempt
def index(request):
    if 'data' not in request.session:
        reset_to_initial(request)

    message = request.session.pop('message', None)

    if request.method == 'POST':
        if 'clear' in request.POST:
            reset_to_initial(request)
            return redirect(request.path)

        ip_input = request.POST.get('ip', '').strip()
        bulk_ips = request.POST.get('bulk_ips', '').strip()
        added = False
        msg_text = None
        msg_type = "info"

        if ip_input and re.match(r'^(\d{1,3}\.){3}\d{1,3}$', ip_input):
            exists = any(item['ip'] == ip_input for item in request.session['data'])
            if not exists:
                connections = random.randint(1, 250)
                suspicious_port = random.choice([0, 1])
                unknown_process = random.choice([0, 1])
                high_traffic = random.choice([0, 1])
                night_activity = random.choice([0, 1])
                c2 = 1 if random.random() < 0.33 else 0
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

        elif bulk_ips:
            ips = re.split(r'[,\s\n]+', bulk_ips)
            added_count = 0
            for ip in ips:
                ip = ip.strip()
                if not ip or not re.match(r'^(\d{1,3}\.){3}\d{1,3}$', ip):
                    continue
                if any(item['ip'] == ip for item in request.session['data']):
                    continue
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
            return redirect(request.path)

    context = {"data": request.session['data'], "message": message}
    return render(request, 'botchecker/index.html', context)


# ========== СТРАНИЦА АНАЛИТИКИ И ЭКСПОРТА ==========

def analytics(request):
    """Страница аналитики и экспорта данных"""
    data = request.session.get('data', [])
    if not data:
        context = {
            'has_data': False,
            'message': 'Нет данных для анализа. Сначала добавьте IP-адреса на главной странице.'
        }
        return render(request, 'botchecker/analytics.html', context)

    total = len(data)
    block_count = sum(1 for row in data if row['decision'] == 'BLOCK')
    allow_count = total - block_count
    block_percent = round(block_count / total * 100, 1) if total > 0 else 0
    allow_percent = round(allow_count / total * 100, 1) if total > 0 else 0

    c2_count = sum(1 for row in data if row['c2_server'] == 1)
    c2_percent = round(c2_count / total * 100, 1) if total > 0 else 0

    threat_levels = [row['threat_level'] for row in data]
    avg_threat = round(sum(threat_levels) / total, 1) if total > 0 else 0
    max_threat = max(threat_levels) if threat_levels else 0
    min_threat = min(threat_levels) if threat_levels else 0

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


def export_csv(request):
    """Экспорт таблицы в CSV"""
    data = request.session.get('data', [])
    if not data:
        return HttpResponse("Нет данных для экспорта", status=404)

    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = 'attachment; filename="bot_analysis.csv"'

    writer = csv.writer(response)
    writer.writerow(['ID', 'IP адрес', 'Соединений', 'Подозр. порт', 'Подозр. процесс',
                     'Высокий трафик', 'C&C сервер', 'Ночная активность', 'Уровень угрозы', 'Решение'])
    for row in data:
        writer.writerow([row['id'], row['ip'], row['connections'], row['suspicious_port'],
                         row['unknown_process'], row['high_traffic'], row['c2_server'],
                         row['night_activity'], row['threat_level'], row['decision']])
    return response


def export_excel(request):
    """Экспорт таблицы в Excel (XLSX)"""
    data = request.session.get('data', [])
    if not data:
        return HttpResponse("Нет данных для экспорта", status=404)

    response = HttpResponse(content_type='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')
    response['Content-Disposition'] = 'attachment; filename="bot_analysis.xlsx"'

    output = io.BytesIO()
    workbook = xlsxwriter.Workbook(output)
    worksheet = workbook.add_worksheet('Результаты анализа')

    headers = ['ID', 'IP адрес', 'Соединений', 'Подозр. порт', 'Подозр. процесс',
               'Высокий трафик', 'C&C сервер', 'Ночная активность', 'Уровень угрозы', 'Решение']
    for col, header in enumerate(headers):
        worksheet.write(0, col, header)

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