"""
Модуль для извлечения признаков из сетевого трафика (PCAP файлов).
"""

import pandas as pd
from scapy.all import rdpcap, IP, TCP, UDP, ICMP
from collections import defaultdict
import os


def _normalize_flow_key(src_ip, dst_ip, src_port, dst_port, protocol):
    """
    Нормализует ключ потока, чтобы поток в обе стороны считался одним.
    Возвращает каноническую форму (меньший IP/порт как источник).
    """
    # Сравниваем IP адреса
    if src_ip > dst_ip:
        src_ip, dst_ip = dst_ip, src_ip
        src_port, dst_port = dst_port, src_port
    elif src_ip == dst_ip:
        # Если IP одинаковые, сравниваем порты
        if src_port > dst_port:
            src_port, dst_port = dst_port, src_port
    
    return (src_ip, dst_ip, src_port, dst_port, protocol)


def _get_protocol_name(packet):
    """
    Определяет протокол пакета.
    """
    if packet.haslayer(TCP):
        return 'TCP'
    elif packet.haslayer(UDP):
        return 'UDP'
    elif packet.haslayer(ICMP):
        return 'ICMP'
    else:
        return 'OTHER'


def _get_ports(packet):
    """
    Извлекает порты источника и назначения из пакета.
    """
    src_port = 0
    dst_port = 0
    
    if packet.haslayer(TCP):
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
    elif packet.haslayer(UDP):
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport
    
    return src_port, dst_port


def extract_features_from_pcap(pcap_file, output_csv="data/traffic_features.csv", is_anomaly=0):
    """
    Извлекает признаки из PCAP файла и сохраняет их в CSV.
    
    Args:
        pcap_file: Путь к PCAP файлу
        output_csv: Путь к файлу для сохранения признаков
        is_anomaly: Метка аномалии (0 = нормальный, 1 = аномальный). По умолчанию 0.
    
    Returns:
        pd.DataFrame: DataFrame с извлеченными признаками
    """
    if not os.path.exists(pcap_file):
        raise FileNotFoundError(f"PCAP файл не найден: {pcap_file}")
    
    print(f"📦 Чтение PCAP файла: {pcap_file}")
    packets = rdpcap(pcap_file)
    print(f"   Найдено пакетов: {len(packets)}")
    
    # Словарь для хранения потоков
    flows = defaultdict(lambda: {
        'packets': [],
        'timestamps': [],
        'src_ip': None,
        'dst_ip': None,
        'src_port': None,
        'dst_port': None,
        'protocol': None,
        'ips': set()
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
        flow['ips'].add(src_ip)
        flow['ips'].add(dst_ip)
    
    print(f"   Найдено потоков: {len(flows)}")
    
    # Извлекаем признаки для каждого потока
    features = []
    
    for flow_key, flow_data in flows.items():
        packets = flow_data['packets']
        timestamps = flow_data['timestamps']
        
        if len(packets) == 0:
            continue
        
        # Базовые признаки
        packet_count = len(packets)
        total_bytes = sum(len(p) for p in packets)
        
        # Временные характеристики
        start_time = min(timestamps)
        end_time = max(timestamps)
        duration = max(end_time - start_time, 0.001)  # Минимум 1мс, чтобы избежать деления на ноль
        avg_speed = total_bytes / duration if duration > 0 else 0
        
        # TCP флаги (только для TCP)
        syn_count = 0
        ack_count = 0
        fin_count = 0
        rst_count = 0
        
        if flow_data['protocol'] == 'TCP':
            for packet in packets:
                if packet.haslayer(TCP):
                    tcp = packet[TCP]
                    if tcp.flags & 0x02:  # SYN
                        syn_count += 1
                    if tcp.flags & 0x10:  # ACK
                        ack_count += 1
                    if tcp.flags & 0x01:  # FIN
                        fin_count += 1
                    if tcp.flags & 0x04:  # RST
                        rst_count += 1
        
        # Количество уникальных IP адресов
        unique_ips = len(flow_data['ips'])
        
        # Формируем запись признаков
        feature_row = {
            'packet_count': packet_count,
            'total_bytes': total_bytes,
            'duration': duration,
            'avg_speed': avg_speed,
            'syn_count': syn_count,
            'ack_count': ack_count,
            'fin_count': fin_count,
            'rst_count': rst_count,
            'protocol': flow_data['protocol'],
            'src_port': flow_data['src_port'],
            'dst_port': flow_data['dst_port'],
            'unique_ips': unique_ips,
            'is_anomaly': is_anomaly
        }
        
        features.append(feature_row)
    
    # Создаем DataFrame
    df = pd.DataFrame(features)
    
    # Создаем директорию для выходного файла, если её нет
    output_dir = os.path.dirname(output_csv)
    if output_dir and not os.path.exists(output_dir):
        os.makedirs(output_dir, exist_ok=True)
    
    # Сохраняем в CSV
    df.to_csv(output_csv, index=False)
    print(f"✅ Признаки сохранены в: {output_csv}")
    print(f"   Извлечено признаков: {len(df)}")
    
    return df


if __name__ == "__main__":
    # Пример использования
    import sys
    
    if len(sys.argv) < 2:
        print("Использование: python feature_extractor.py <pcap_file> [output_csv] [is_anomaly]")
        sys.exit(1)
    
    pcap_file = sys.argv[1]
    output_csv = sys.argv[2] if len(sys.argv) > 2 else "data/traffic_features.csv"
    is_anomaly = int(sys.argv[3]) if len(sys.argv) > 3 else 0
    
    extract_features_from_pcap(pcap_file, output_csv, is_anomaly)
