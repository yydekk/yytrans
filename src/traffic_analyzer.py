"""
Модуль для анализа PCAP файлов и обнаружения аномалий в сетевом трафике.
"""

import pandas as pd
import os
import json
import html
from feature_extractor import extract_features_from_pcap
from anomaly_detector import AnomalyDetector


def _extract_flow_metadata(pcap_file):
    """
    Извлекает метаданные потоков (IP адреса, timestamp) из PCAP файла.
    Возвращает словарь, где ключ - это индекс потока, а значение - метаданные.
    """
    from scapy.all import rdpcap, IP, TCP, UDP, ICMP
    from collections import defaultdict
    from feature_extractor import _normalize_flow_key, _get_protocol_name, _get_ports
    
    packets = rdpcap(pcap_file)
    flows = defaultdict(lambda: {
        'packets': [],
        'timestamps': [],
        'src_ip': None,
        'dst_ip': None,
        'src_port': None,
        'dst_port': None,
        'protocol': None
    })
    
    # Обрабатываем каждый пакет
    for packet in packets:
        if not packet.haslayer(IP):
            continue
        
        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        
        protocol_name = _get_protocol_name(packet)
        src_port, dst_port = _get_ports(packet)
        
        # Нормализуем ключ потока
        flow_key = _normalize_flow_key(src_ip, dst_ip, src_port, dst_port, protocol_name)
        
        # Сохраняем информацию о потоке
        flow = flows[flow_key]
        flow['packets'].append(packet)
        flow['timestamps'].append(float(packet.time))
        flow['src_ip'] = flow_key[0]
        flow['dst_ip'] = flow_key[1]
        flow['src_port'] = flow_key[2]
        flow['dst_port'] = flow_key[3]
        flow['protocol'] = flow_key[4]
    
    # Создаем список метаданных в том же порядке, что и признаки
    # Сортируем потоки по ключу для гарантии одинакового порядка
    metadata_list = []
    sorted_flows = sorted(flows.items(), key=lambda x: x[0])
    
    for flow_key, flow_data in sorted_flows:
        if len(flow_data['packets']) == 0:
            continue
        
        start_time = min(flow_data['timestamps'])
        metadata_list.append({
            'src_ip': flow_data['src_ip'],
            'dst_ip': flow_data['dst_ip'],
            'src_port': flow_data['src_port'],
            'dst_port': flow_data['dst_port'],
            'protocol': flow_data['protocol'],
            'timestamp': start_time
        })
    
    return metadata_list


def _parse_http_request(payload_text):
    """
    Парсит HTTP запрос и извлекает детальную информацию.
    Возвращает словарь с полями запроса.
    """
    http_info = {
        "request_line": "",
        "method": "",
        "path": "",
        "http_version": "",
        "headers": {},
        "body": "",
        "user_agent": "",
        "content_type": "",
        "content_length": "",
        "host": "",
        "cookie": "",
        "accept": "",
        "accept_language": "",
        "accept_encoding": "",
        "origin": "",
        "referer": "",
        "connection": "",
        "upgrade_insecure_requests": ""
    }
    
    if not payload_text:
        return http_info
    
    try:
        lines = payload_text.split('\n')
        if not lines:
            return http_info
        
        # Первая строка - Request Line
        first_line = lines[0].strip()
        if first_line:
            http_info["request_line"] = first_line
            parts = first_line.split()
            if len(parts) >= 3:
                http_info["method"] = parts[0]
                http_info["path"] = parts[1]
                http_info["http_version"] = parts[2]
        
        # Парсим заголовки
        body_start = -1
        for i, line in enumerate(lines[1:], 1):
            line = line.strip()
            if not line:
                body_start = i
                break
            
            if ':' in line:
                key, value = line.split(':', 1)
                key = key.strip().lower()
                value = value.strip()
                http_info["headers"][key] = value
                
                # Извлекаем специфичные заголовки
                if key == 'user-agent':
                    http_info["user_agent"] = value
                elif key == 'content-type':
                    http_info["content_type"] = value
                elif key == 'content-length':
                    http_info["content_length"] = value
                elif key == 'host':
                    http_info["host"] = value
                elif key == 'cookie':
                    http_info["cookie"] = value
                elif key == 'accept':
                    http_info["accept"] = value
                elif key == 'accept-language':
                    http_info["accept_language"] = value
                elif key == 'accept-encoding':
                    http_info["accept_encoding"] = value
                elif key == 'origin':
                    http_info["origin"] = value
                elif key == 'referer':
                    http_info["referer"] = value
                elif key == 'connection':
                    http_info["connection"] = value
                elif key == 'upgrade-insecure-requests':
                    http_info["upgrade_insecure_requests"] = value
        
        # Тело запроса
        if body_start > 0 and body_start < len(lines):
            http_info["body"] = '\n'.join(lines[body_start:]).strip()
    
    except Exception as e:
        pass  # Если парсинг не удался, возвращаем базовую информацию
    
    return http_info


def _extract_packets(pcap_file, output_json="data/packets.json", max_payload_bytes=4096):
    """
    Извлекает список пакетов из PCAP/PCAPNG для последующего просмотра на дашборде.
    Сохраняет данные в JSON.
    """
    from scapy.all import rdpcap, IP, TCP, UDP, ICMP, Raw
    from feature_extractor import _get_protocol_name, _get_ports
    from io import StringIO
    import contextlib
    from datetime import datetime

    packets = rdpcap(pcap_file)
    packet_rows = []

    for idx, packet in enumerate(packets):
        ts = float(packet.time)
        src_ip = packet[IP].src if packet.haslayer(IP) else ""
        dst_ip = packet[IP].dst if packet.haslayer(IP) else ""
        protocol_name = _get_protocol_name(packet)
        src_port, dst_port = _get_ports(packet)
        raw_bytes = bytes(packet)
        payload_bytes = raw_bytes[:max_payload_bytes]

        # Полный вывод пакета (как в scapy.show) — с защитой от ошибок
        details = ""
        with contextlib.redirect_stdout(StringIO()) as buf:
            try:
                packet.show()
                details = buf.getvalue()
            except Exception:
                details = packet.summary() if hasattr(packet, "summary") else ""

        # Попытка декодировать полезную нагрузку в текст
        readable_payload = ""
        http_info = {}
        
        # Извлекаем TCP payload если есть
        if packet.haslayer(Raw):
            try:
                tcp_payload = packet[Raw].load
                readable_payload = tcp_payload.decode("utf-8", errors="replace")
                # Парсим HTTP если это HTTP запрос
                if readable_payload.startswith(('GET ', 'POST ', 'PUT ', 'DELETE ', 'HEAD ', 'OPTIONS ', 'PATCH ')):
                    http_info = _parse_http_request(readable_payload)
            except Exception:
                pass
        
        if not readable_payload and payload_bytes:
            try:
                readable_payload = payload_bytes.decode("utf-8", errors="replace")
                if readable_payload.startswith(('GET ', 'POST ', 'PUT ', 'DELETE ', 'HEAD ', 'OPTIONS ', 'PATCH ')):
                    http_info = _parse_http_request(readable_payload)
            except Exception:
                readable_payload = ""

        # Форматируем время в читаемый формат
        try:
            dt = datetime.fromtimestamp(ts)
            time_formatted = dt.strftime("%d-%m-%Y %H:%M")
        except:
            time_formatted = str(ts)

        # Готовим HTML-версию в формате как на фото
        if http_info and http_info.get("request_line"):
            # HTTP запрос - показываем в красивом формате
            details_html_parts = [
                '<div style="background:#fff; color:#333; padding:20px; border-radius:8px; font-family:monospace; border:1px solid #e9ecef;">',
                '<div style="margin-bottom:20px;">',
                '<h3 style="color:#667eea; margin:0 0 15px 0; font-size:1.1em;">Request information</h3>',
                f'<div style="margin-bottom:8px;"><span style="color:#666; font-weight:600;">Request id:</span> <span style="color:#333;">{idx}</span></div>',
                f'<div style="margin-bottom:8px;"><span style="color:#666; font-weight:600;">Request time:</span> <span style="color:#333;">{time_formatted}</span></div>',
                f'<div style="margin-bottom:8px;"><span style="color:#666; font-weight:600;">From:</span> <span style="color:#333;">{html.escape(src_ip)}</span></div>',
                f'<div style="margin-bottom:8px;"><span style="color:#666; font-weight:600;">To:</span> <span style="color:#333;">{html.escape(dst_ip)}</span></div>',
                f'<div style="margin-bottom:8px;"><span style="color:#666; font-weight:600;">Protocol:</span> <span style="color:#333;">{html.escape(protocol_name)}</span></div>',
                f'<div style="margin-bottom:8px;"><span style="color:#666; font-weight:600;">Port:</span> <span style="color:#333;">{dst_port}</span></div>',
                f'<div style="margin-bottom:8px;"><span style="color:#666; font-weight:600;">Payload length:</span> <span style="color:#333;">{len(packet)} bytes</span></div>',
                '</div>',
                '<div style="border-top:1px solid #e9ecef; padding-top:20px; margin-top:20px;">',
                '<h3 style="color:#667eea; margin:0 0 15px 0; font-size:1.1em;">Payload</h3>',
            ]
            
            # Request Line
            if http_info.get("request_line"):
                details_html_parts.append(f'<div style="margin-bottom:8px;"><span style="color:#666; font-weight:600;">Request Line:</span> <span style="color:#333;">{html.escape(http_info["request_line"])}</span></div>')
            
            # Headers
            if http_info.get("host"):
                details_html_parts.append(f'<div style="margin-bottom:8px;"><span style="color:#666; font-weight:600;">Host:</span> <span style="color:#333;">{html.escape(http_info["host"])}</span></div>')
            if http_info.get("user_agent"):
                details_html_parts.append(f'<div style="margin-bottom:8px;"><span style="color:#666; font-weight:600;">User-Agent:</span> <span style="color:#333;">{html.escape(http_info["user_agent"])}</span></div>')
            if http_info.get("accept"):
                details_html_parts.append(f'<div style="margin-bottom:8px;"><span style="color:#666; font-weight:600;">Accept:</span> <span style="color:#333;">{html.escape(http_info["accept"])}</span></div>')
            if http_info.get("accept_language"):
                details_html_parts.append(f'<div style="margin-bottom:8px;"><span style="color:#666; font-weight:600;">Accept-Language:</span> <span style="color:#333;">{html.escape(http_info["accept_language"])}</span></div>')
            if http_info.get("accept_encoding"):
                details_html_parts.append(f'<div style="margin-bottom:8px;"><span style="color:#666; font-weight:600;">Accept-Encoding:</span> <span style="color:#333;">{html.escape(http_info["accept_encoding"])}</span></div>')
            if http_info.get("content_type"):
                details_html_parts.append(f'<div style="margin-bottom:8px;"><span style="color:#666; font-weight:600;">Content-Type:</span> <span style="color:#333;">{html.escape(http_info["content_type"])}</span></div>')
            if http_info.get("content_length"):
                details_html_parts.append(f'<div style="margin-bottom:8px;"><span style="color:#666; font-weight:600;">Content-Length:</span> <span style="color:#333;">{html.escape(http_info["content_length"])}</span></div>')
            if http_info.get("origin"):
                details_html_parts.append(f'<div style="margin-bottom:8px;"><span style="color:#666; font-weight:600;">Origin:</span> <span style="color:#333;">{html.escape(http_info["origin"])}</span></div>')
            if http_info.get("connection"):
                details_html_parts.append(f'<div style="margin-bottom:8px;"><span style="color:#666; font-weight:600;">Connection:</span> <span style="color:#333;">{html.escape(http_info["connection"])}</span></div>')
            if http_info.get("referer"):
                details_html_parts.append(f'<div style="margin-bottom:8px;"><span style="color:#666; font-weight:600;">Referer:</span> <span style="color:#333;">{html.escape(http_info["referer"])}</span></div>')
            if http_info.get("cookie"):
                details_html_parts.append(f'<div style="margin-bottom:8px;"><span style="color:#666; font-weight:600;">Cookie:</span> <span style="color:#333;">{html.escape(http_info["cookie"])}</span></div>')
            if http_info.get("upgrade_insecure_requests"):
                details_html_parts.append(f'<div style="margin-bottom:8px;"><span style="color:#666; font-weight:600;">Upgrade-Insecure-Requests:</span> <span style="color:#333;">{html.escape(http_info["upgrade_insecure_requests"])}</span></div>')
            
            # Body
            if http_info.get("body"):
                details_html_parts.append(f'<div style="margin-top:15px;"><span style="color:#666; font-weight:600;">Body:</span></div>')
                details_html_parts.append(f'<pre style="background:#f8f9fa; padding:10px; border-radius:4px; margin-top:5px; overflow:auto; color:#333; border:1px solid #e9ecef;">{html.escape(http_info["body"])}</pre>')
            
            details_html_parts.append('</div></div>')
            details_html = "\n".join(details_html_parts)
        else:
            # Не HTTP - обычный формат
            details_html_parts = [
                f"<strong>Timestamp:</strong> {ts}",
                f"<strong>Source:</strong> {html.escape(src_ip)}:{src_port}",
                f"<strong>Destination:</strong> {html.escape(dst_ip)}:{dst_port}",
                f"<strong>Protocol:</strong> {protocol_name}",
                f"<strong>Port:</strong> {dst_port}",
                f"<strong>Length:</strong> {len(packet)}",
                "<hr>",
                "<strong>Summary</strong><br>",
                f"<pre style='white-space:pre-wrap;margin:0;'>{html.escape(packet.summary() if hasattr(packet, 'summary') else '')}</pre>",
            ]

            if readable_payload:
                details_html_parts.extend([
                    "<hr>",
                    "<strong>Payload (text)</strong><br>",
                    f"<pre style='white-space:pre-wrap;margin:0;'>{html.escape(readable_payload)}</pre>",
                ])

            if payload_bytes:
                details_html_parts.extend([
                    "<hr>",
                    "<strong>Payload (hex, truncated)</strong><br>",
                    f"<pre style='white-space:pre-wrap;margin:0;'>{payload_bytes.hex()}</pre>",
                ])

            if details:
                details_html_parts.extend([
                    "<hr>",
                    "<strong>Scapy details</strong><br>",
                    f"<pre style='white-space:pre-wrap;margin:0;'>{html.escape(details)}</pre>",
                ])

            details_html = "\n".join(details_html_parts)

        packet_rows.append({
            "id": idx,
            "timestamp": ts,
            "time_formatted": time_formatted,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "protocol": protocol_name,
            "length": len(packet),
            "summary": packet.summary() if hasattr(packet, "summary") else "",
            "payload_hex": payload_bytes.hex(),
            "payload_hex_full": raw_bytes.hex(),
            "details": details,
            "readable_payload": readable_payload,
            "details_html": details_html,
            "http_info": http_info
        })

    output_dir = os.path.dirname(output_json)
    if output_dir and not os.path.exists(output_dir):
        os.makedirs(output_dir, exist_ok=True)

    with open(output_json, "w", encoding="utf-8") as f:
        json.dump(packet_rows, f, ensure_ascii=False)

    return packet_rows


def _determine_alert_level(anomaly_score, packet_count, rst_count, syn_count):
    """
    Определяет уровень критичности аномалии на основе признаков.
    
    Args:
        anomaly_score: Оценка аномалии (меньше 0 = аномалия)
        packet_count: Количество пакетов в потоке
        rst_count: Количество RST флагов
        syn_count: Количество SYN флагов
    
    Returns:
        str: Уровень критичности (LOW, MEDIUM, HIGH, CRITICAL)
    """
    # Чем меньше anomaly_score, тем выше критичность
    # Нормализуем score: обычно от -0.5 до 0.5, где меньше = хуже
    score_normalized = abs(anomaly_score) if anomaly_score < 0 else 0
    
    # Критерии для определения уровня
    if score_normalized > 0.3 or (packet_count > 1000 and rst_count > 10):
        return "CRITICAL"
    elif score_normalized > 0.2 or (packet_count > 500 and syn_count > 50):
        return "HIGH"
    elif score_normalized > 0.1 or packet_count > 100:
        return "MEDIUM"
    elif score_normalized > 0:
        return "LOW"
    else:
        return "NORMAL"


def analyze_traffic(pcap_file, model_path=None, output_csv="data/analysis_results.csv"):
    """
    Анализирует PCAP файл и обнаруживает аномалии.
    
    Args:
        pcap_file: Путь к PCAP файлу для анализа
        model_path: Путь к обученной модели (обязательно для обнаружения аномалий)
        output_csv: Путь к файлу для сохранения результатов
    
    Returns:
        dict: Статистика анализа
    """
    if not os.path.exists(pcap_file):
        raise FileNotFoundError(f"PCAP файл не найден: {pcap_file}")
    
    print("=" * 60)
    print("🔍 Анализ сетевого трафика")
    print("=" * 60)
    print(f"📦 PCAP файл: {pcap_file}")
    
    # Шаг 1: Извлечение признаков
    print("\n📊 Шаг 1: Извлечение признаков из трафика...")
    temp_features_file = "data/temp_features.csv"
    features_df = extract_features_from_pcap(pcap_file, temp_features_file, is_anomaly=0)
    
    if len(features_df) == 0:
        print("⚠️  Не удалось извлечь признаки из PCAP файла")
        return None
    
    # Шаг 2: Извлечение метаданных потоков
    print("\n📋 Шаг 2: Извлечение метаданных потоков...")
    metadata_list = _extract_flow_metadata(pcap_file)
    
    # Создаем словарь для быстрого поиска метаданных по ключу потока
    # Используем комбинацию портов и протокола как ключ
    metadata_dict = {}
    for meta in metadata_list:
        key = (meta['src_port'], meta['dst_port'], meta['protocol'])
        # Если ключ уже существует, берем первый (они должны быть одинаковыми после нормализации)
        if key not in metadata_dict:
            metadata_dict[key] = meta
    
    # Проверяем соответствие количества потоков
    if len(metadata_list) != len(features_df):
        print(f"⚠️  Предупреждение: количество потоков не совпадает ({len(metadata_list)} vs {len(features_df)})")
        print(f"   Используется сопоставление по признакам потоков")
    
    # Шаг 3: Обнаружение аномалий
    print("\n🤖 Шаг 3: Обнаружение аномалий...")
    
    if model_path is None or not os.path.exists(model_path):
        print("⚠️  Модель не указана или не найдена. Используется базовая эвристика.")
        # Базовая эвристика для определения аномалий
        anomaly_scores = []
        is_anomaly_list = []
        
        for idx, row in features_df.iterrows():
            # Простая эвристика: много RST, много SYN, необычные порты
            score = 0.0
            if row['rst_count'] > 5:
                score -= 0.3
            if row['syn_count'] > 20 and row['packet_count'] < 10:
                score -= 0.2
            if row['packet_count'] > 1000:
                score -= 0.2
            if row['dst_port'] < 1024 and row['src_port'] > 49152:
                score -= 0.1
            
            anomaly_scores.append(score)
            is_anomaly_list.append(1 if score < -0.1 else 0)
    else:
        # Используем обученную модель
        print(f"   Загрузка модели: {model_path}")
        detector = AnomalyDetector()
        detector.load_model(model_path)
        
        # Получаем предсказания и оценки
        predictions = detector.predict(features_df)
        anomaly_scores = detector.predict_anomaly_scores(features_df)
        
        # Преобразуем предсказания: -1 = аномалия, 1 = нормальный
        is_anomaly_list = (predictions == -1).astype(int).tolist()
        # Инвертируем scores для удобства (меньше = хуже)
        anomaly_scores = (-anomaly_scores).tolist()
    
    # Шаг 4: Формирование результатов
    print("\n💾 Шаг 4: Сохранение результатов...")
    
    results = []
    for idx, row in features_df.iterrows():
        anomaly_score = anomaly_scores[idx] if idx < len(anomaly_scores) else 0.0
        is_anomaly = is_anomaly_list[idx] if idx < len(is_anomaly_list) else 0
        
        # Находим метаданные по ключу потока
        flow_key = (row['src_port'], row['dst_port'], row['protocol'])
        
        if flow_key in metadata_dict:
            metadata = metadata_dict[flow_key]
        elif idx < len(metadata_list):
            # Fallback: используем индекс, если есть
            metadata = metadata_list[idx]
        else:
            # Если метаданных нет, используем значения из features_df
            metadata = {
                'src_ip': '0.0.0.0',  # Значение по умолчанию
                'dst_ip': '0.0.0.0',
                'src_port': row['src_port'],
                'dst_port': row['dst_port'],
                'protocol': row['protocol'],
                'timestamp': 0.0
            }
        
        # Определяем уровень критичности
        alert_level = _determine_alert_level(
            anomaly_score,
            row['packet_count'],
            row['rst_count'],
            row['syn_count']
        )

        result_row = {
            'timestamp': metadata['timestamp'],
            'src_ip': metadata['src_ip'],
            'dst_ip': metadata['dst_ip'],
            'src_port': metadata['src_port'],
            'dst_port': metadata['dst_port'],
            'protocol': metadata['protocol'],
            'packet_count': row['packet_count'],
            'anomaly_score': anomaly_score,
            'is_anomaly': is_anomaly,
            'alert_level': alert_level
        }
        
        results.append(result_row)
    
    # Создаем DataFrame с результатами
    results_df = pd.DataFrame(results)
    
    # Создаем директорию для выходного файла
    output_dir = os.path.dirname(output_csv)
    if output_dir and not os.path.exists(output_dir):
        os.makedirs(output_dir, exist_ok=True)
    
    # Сохраняем результаты
    results_df.to_csv(output_csv, index=False)
    print(f"✅ Результаты сохранены: {output_csv}")
    
    # Удаляем временный файл
    if os.path.exists(temp_features_file):
        os.remove(temp_features_file)
    
    # Дополнительно сохраняем список пакетов для просмотра в дашборде
    try:
        # Сохраняем packets.json в ту же директорию, что и output_csv
        packets_json_path = os.path.join(output_dir, "packets.json") if output_dir else "data/packets.json"
        _extract_packets(pcap_file, output_json=packets_json_path)
        print(f"📦 Список пакетов сохранен в {packets_json_path}")
    except Exception as e:
        print(f"⚠️  Не удалось сохранить список пакетов: {e}")
    
    # Шаг 5: Генерация отчета
    print("\n📊 Шаг 5: Генерация отчета...")
    stats = _generate_report(results_df, output_csv)
    
    return stats


def _generate_report(results_df, output_csv):
    """
    Генерирует отчет об анализе трафика.
    
    Args:
        results_df: DataFrame с результатами анализа
        output_csv: Путь к файлу с результатами
    
    Returns:
        dict: Статистика анализа
    """
    total_flows = len(results_df)
    anomalies = results_df[results_df['is_anomaly'] == 1]
    num_anomalies = len(anomalies)
    anomaly_percentage = (num_anomalies / total_flows * 100) if total_flows > 0 else 0
    
    # Подозрительные IP адреса (IP, которые участвуют в аномалиях)
    suspicious_ips = set()
    if num_anomalies > 0:
        suspicious_ips.update(anomalies['src_ip'].unique())
        suspicious_ips.update(anomalies['dst_ip'].unique())
    
    # Статистика по уровням критичности
    alert_levels = results_df['alert_level'].value_counts().to_dict()
    
    # Статистика по типам аномалий (на основе признаков)
    anomaly_stats = {}
    if num_anomalies > 0:
        anomaly_stats = {
            'high_rst_count': len(anomalies[anomalies['packet_count'] > 0]),  # Упрощенная статистика
            'high_packet_count': len(anomalies[anomalies['packet_count'] > 500]),
            'suspicious_ports': len(anomalies[(anomalies['dst_port'] < 1024) & (anomalies['src_port'] > 49152)])
        }
    
    # Выводим отчет
    print("\n" + "=" * 60)
    print("📈 ОТЧЕТ ОБ АНАЛИЗЕ ТРАФИКА")
    print("=" * 60)
    print(f"Общее количество потоков:     {total_flows}")
    print(f"Обнаружено аномалий:           {num_anomalies} ({anomaly_percentage:.2f}%)")
    print(f"Подозрительных IP адресов:    {len(suspicious_ips)}")
    
    if suspicious_ips:
        print(f"\n🔴 Топ-10 подозрительных IP адресов:")
        # Подсчитываем количество аномалий для каждого IP
        ip_counts = {}
        for _, row in anomalies.iterrows():
            for ip in [row['src_ip'], row['dst_ip']]:
                ip_counts[ip] = ip_counts.get(ip, 0) + 1
        
        # Сортируем по количеству аномалий
        sorted_ips = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:10]
        for ip, count in sorted_ips:
            print(f"   {ip:15s} - {count} аномалий")
    
    print(f"\n📊 Распределение по уровням критичности:")
    for level in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'NORMAL']:
        count = alert_levels.get(level, 0)
        if count > 0:
            print(f"   {level:10s}: {count:4d} потоков")
    
    if anomaly_stats:
        print(f"\n🔍 Статистика по типам аномалий:")
        print(f"   Потоков с большим количеством пакетов: {anomaly_stats.get('high_packet_count', 0)}")
        print(f"   Потоков с подозрительными портами:     {anomaly_stats.get('suspicious_ports', 0)}")
    
    print("=" * 60)
    
    # Формируем словарь статистики
    stats = {
        'total_flows': total_flows,
        'num_anomalies': num_anomalies,
        'anomaly_percentage': anomaly_percentage,
        'suspicious_ips': list(suspicious_ips),
        'alert_levels': alert_levels,
        'anomaly_stats': anomaly_stats,
        'output_file': output_csv
    }
    
    return stats


if __name__ == "__main__":
    # Пример использования
    import sys
    
    if len(sys.argv) < 2:
        print("Использование: python traffic_analyzer.py <pcap_file> [model_path] [output_csv]")
        print("\nПримеры:")
        print("  python traffic_analyzer.py data/mixed_traffic.pcap")
        print("  python traffic_analyzer.py data/mixed_traffic.pcap models/anomaly_detector.pkl")
        print("  python traffic_analyzer.py data/mixed_traffic.pcap models/anomaly_detector.pkl data/results.csv")
        sys.exit(1)
    
    pcap_file = sys.argv[1]
    model_path = sys.argv[2] if len(sys.argv) > 2 else None
    output_csv = sys.argv[3] if len(sys.argv) > 3 else "data/analysis_results.csv"
    
    stats = analyze_traffic(pcap_file, model_path, output_csv)
    
    if stats:
        print(f"\n✅ Анализ завершен успешно!")
        print(f"📄 Результаты сохранены в: {stats['output_file']}")
