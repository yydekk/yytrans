"""
Скрипт для генерации тестовых PCAP файлов с нормальным и подозрительным трафиком.
"""

import random
import time
from scapy.all import IP, TCP, UDP, DNS, DNSQR, DNSRR, Raw, wrpcap
import os


def generate_normal_traffic(output_file="data/normal_traffic.pcap", num_flows=50):
    """
    Генерирует нормальный трафик (HTTP, HTTPS, DNS).
    
    Args:
        output_file: Путь к выходному PCAP файлу
        num_flows: Количество потоков для генерации
    """
    print(f"🌐 Генерация нормального трафика...")
    packets = []
    
    # Базовые IP адреса
    client_ip = "192.168.1.100"
    server_ips = ["10.0.0.1", "10.0.0.2", "10.0.0.3", "8.8.8.8", "1.1.1.1"]
    
    base_time = time.time()
    current_time = base_time
    
    for i in range(num_flows):
        # Случайный интервал между запросами (1-5 секунд)
        if i > 0:
            current_time += random.uniform(1.0, 5.0)
        
        # Выбираем случайный тип трафика
        traffic_type = random.choice(['http', 'https', 'dns'])
        server_ip = random.choice(server_ips)
        src_port = random.randint(49152, 65535)  # Эфемерные порты
        
        if traffic_type == 'http':
            # HTTP запрос на порт 80
            dst_port = 80
            packet_size = random.randint(500, 1500)
            
            # TCP SYN
            syn_packet = IP(src=client_ip, dst=server_ip) / TCP(
                sport=src_port, dport=dst_port, flags="S", seq=random.randint(1000, 99999)
            )
            syn_packet.time = current_time
            packets.append(syn_packet)
            
            # TCP SYN-ACK (ответ сервера)
            syn_ack_packet = IP(src=server_ip, dst=client_ip) / TCP(
                sport=dst_port, dport=src_port, flags="SA", 
                seq=random.randint(1000, 99999), ack=syn_packet[TCP].seq + 1
            )
            syn_ack_packet.time = current_time + 0.01
            packets.append(syn_ack_packet)
            
            # TCP ACK
            ack_packet = IP(src=client_ip, dst=server_ip) / TCP(
                sport=src_port, dport=dst_port, flags="A",
                seq=syn_packet[TCP].seq + 1, ack=syn_ack_packet[TCP].seq + 1
            )
            ack_packet.time = current_time + 0.02
            packets.append(ack_packet)
            
            # HTTP запрос
            http_data = f"GET /index.html HTTP/1.1\r\nHost: {server_ip}\r\n\r\n"
            http_packet = IP(src=client_ip, dst=server_ip) / TCP(
                sport=src_port, dport=dst_port, flags="PA",
                seq=ack_packet[TCP].seq, ack=syn_ack_packet[TCP].seq + 1
            ) / Raw(load=http_data)
            http_packet.time = current_time + 0.03
            packets.append(http_packet)
            
            # HTTP ответ (частично заполняем до нужного размера)
            response_data = "HTTP/1.1 200 OK\r\nContent-Length: " + "A" * (packet_size - 100)
            http_response = IP(src=server_ip, dst=client_ip) / TCP(
                sport=dst_port, dport=src_port, flags="PA",
                seq=syn_ack_packet[TCP].seq + 1, ack=http_packet[TCP].seq + len(http_data)
            ) / Raw(load=response_data[:packet_size])
            http_response.time = current_time + 0.1
            packets.append(http_response)
            
            # Закрытие соединения
            fin_packet = IP(src=client_ip, dst=server_ip) / TCP(
                sport=src_port, dport=dst_port, flags="FA",
                seq=http_packet[TCP].seq + len(http_data), ack=http_response[TCP].seq + len(response_data)
            )
            fin_packet.time = current_time + 0.5
            packets.append(fin_packet)
            
        elif traffic_type == 'https':
            # HTTPS запрос на порт 443
            dst_port = 443
            packet_size = random.randint(500, 1500)
            
            # TCP SYN
            syn_packet = IP(src=client_ip, dst=server_ip) / TCP(
                sport=src_port, dport=dst_port, flags="S", seq=random.randint(1000, 99999)
            )
            syn_packet.time = current_time
            packets.append(syn_packet)
            
            # TCP SYN-ACK
            syn_ack_packet = IP(src=server_ip, dst=client_ip) / TCP(
                sport=dst_port, dport=src_port, flags="SA",
                seq=random.randint(1000, 99999), ack=syn_packet[TCP].seq + 1
            )
            syn_ack_packet.time = current_time + 0.01
            packets.append(syn_ack_packet)
            
            # TCP ACK
            ack_packet = IP(src=client_ip, dst=server_ip) / TCP(
                sport=src_port, dport=dst_port, flags="A",
                seq=syn_packet[TCP].seq + 1, ack=syn_ack_packet[TCP].seq + 1
            )
            ack_packet.time = current_time + 0.02
            packets.append(ack_packet)
            
            # HTTPS данные (зашифрованные, имитация)
            https_data = b'\x17\x03\x03' + bytes([random.randint(0, 255) for _ in range(packet_size - 10)])
            https_packet = IP(src=client_ip, dst=server_ip) / TCP(
                sport=src_port, dport=dst_port, flags="PA",
                seq=ack_packet[TCP].seq, ack=syn_ack_packet[TCP].seq + 1
            ) / Raw(load=https_data)
            https_packet.time = current_time + 0.03
            packets.append(https_packet)
            
        elif traffic_type == 'dns':
            # DNS запрос на порт 53
            dst_port = 53
            
            # DNS запрос
            dns_query = DNS(rd=1, qd=DNSQR(qname=random.choice([
                "google.com", "example.com", "github.com", "stackoverflow.com", "wikipedia.org"
            ])))
            dns_packet = IP(src=client_ip, dst=server_ip) / UDP(
                sport=src_port, dport=dst_port
            ) / dns_query
            dns_packet.time = current_time
            packets.append(dns_packet)
            
            # DNS ответ
            dns_response = DNS(id=dns_query.id, qr=1, aa=1, rd=1, ra=1, qd=dns_query.qd,
                             an=DNSRR(rrname=dns_query.qd.qname, ttl=300, rdata="93.184.216.34"))
            dns_response_packet = IP(src=server_ip, dst=client_ip) / UDP(
                sport=dst_port, dport=src_port
            ) / dns_response
            dns_response_packet.time = current_time + 0.05
            packets.append(dns_response_packet)
    
    # Сохраняем пакеты
    output_dir = os.path.dirname(output_file)
    if output_dir and not os.path.exists(output_dir):
        os.makedirs(output_dir, exist_ok=True)
    
    wrpcap(output_file, packets)
    print(f"✅ Нормальный трафик сохранен: {output_file} ({len(packets)} пакетов)")


def generate_suspicious_traffic(output_file="data/suspicious_traffic.pcap"):
    """
    Генерирует подозрительный трафик (порт-сканирование, DDoS, короткие сессии).
    
    Args:
        output_file: Путь к выходному PCAP файлу
    """
    print(f"⚠️  Генерация подозрительного трафика...")
    packets = []
    
    attacker_ip = "192.168.1.200"
    target_ip = "10.0.0.1"
    base_time = time.time()
    current_time = base_time
    
    # 1. Порт-сканирование (много запросов на разные порты за короткое время)
    print("   🔍 Генерация порт-сканирования...")
    scan_ports = list(range(20, 100)) + list(range(2000, 2100))  # Сканируем много портов
    random.shuffle(scan_ports)
    
    for i, port in enumerate(scan_ports[:100]):  # Сканируем 100 портов быстро
        src_port = random.randint(49152, 65535)
        
        # TCP SYN (попытка подключения)
        syn_packet = IP(src=attacker_ip, dst=target_ip) / TCP(
            sport=src_port, dport=port, flags="S", seq=random.randint(1000, 99999)
        )
        syn_packet.time = current_time + i * 0.001  # Очень быстро, каждую миллисекунду
        packets.append(syn_packet)
        
        # RST ответ (порт закрыт или фильтруется)
        rst_packet = IP(src=target_ip, dst=attacker_ip) / TCP(
            sport=port, dport=src_port, flags="R",
            seq=random.randint(1000, 99999), ack=syn_packet[TCP].seq + 1
        )
        rst_packet.time = current_time + i * 0.001 + 0.01
        packets.append(rst_packet)
    
    current_time += 0.2
    
    # 2. DDoS-подобный трафик (очень много пакетов за секунду)
    print("   💥 Генерация DDoS-трафика...")
    ddos_target_ip = "10.0.0.2"
    ddos_port = 80
    
    for i in range(1000):  # 1000 пакетов за короткое время
        src_port = random.randint(49152, 65535)
        
        # Много SYN пакетов (SYN flood)
        syn_packet = IP(src=f"192.168.1.{random.randint(100, 254)}", dst=ddos_target_ip) / TCP(
            sport=src_port, dport=ddos_port, flags="S", seq=random.randint(1000, 99999)
        )
        syn_packet.time = current_time + i * 0.001  # 1000 пакетов в секунду
        packets.append(syn_packet)
    
    current_time += 1.5
    
    # 3. Подозрительно короткие сессии (много RST флагов)
    print("   🔄 Генерация коротких сессий с RST...")
    for i in range(50):
        src_port = random.randint(49152, 65535)
        dst_port = random.randint(1, 1024)
        attacker_variant = f"192.168.1.{random.randint(100, 254)}"
        
        # SYN
        syn_packet = IP(src=attacker_variant, dst=target_ip) / TCP(
            sport=src_port, dport=dst_port, flags="S", seq=random.randint(1000, 99999)
        )
        syn_packet.time = current_time + i * 0.01
        packets.append(syn_packet)
        
        # Сразу RST (подозрительное поведение)
        rst_packet = IP(src=attacker_variant, dst=target_ip) / TCP(
            sport=src_port, dport=dst_port, flags="R",
            seq=syn_packet[TCP].seq + 1, ack=random.randint(1000, 99999)
        )
        rst_packet.time = current_time + i * 0.01 + 0.001
        packets.append(rst_packet)
    
    current_time += 1.0
    
    # 4. Необычные комбинации портов
    print("   🎯 Генерация необычных комбинаций портов...")
    unusual_ports = [(1, 65535), (1024, 1), (53, 80), (443, 22), (8080, 21)]
    
    for src_port, dst_port in unusual_ports:
        for i in range(10):
            syn_packet = IP(src=attacker_ip, dst=target_ip) / TCP(
                sport=src_port, dport=dst_port, flags="S", seq=random.randint(1000, 99999)
            )
            syn_packet.time = current_time + i * 0.1
            packets.append(syn_packet)
        current_time += 1.0
    
    # 5. Аномально большие или маленькие пакеты
    print("   📦 Генерация аномальных размеров пакетов...")
    
    # Очень маленькие пакеты
    for i in range(20):
        tiny_data = b"X" * 10  # Очень маленький пакет
        tiny_packet = IP(src=attacker_ip, dst=target_ip) / TCP(
            sport=random.randint(49152, 65535), dport=80, flags="PA",
            seq=random.randint(1000, 99999)
        ) / Raw(load=tiny_data)
        tiny_packet.time = current_time + i * 0.1
        packets.append(tiny_packet)
    
    current_time += 2.0
    
    # Очень большие пакеты
    for i in range(10):
        huge_data = b"X" * 10000  # Очень большой пакет (10KB)
        huge_packet = IP(src=attacker_ip, dst=target_ip) / TCP(
            sport=random.randint(49152, 65535), dport=80, flags="PA",
            seq=random.randint(1000, 99999)
        ) / Raw(load=huge_data)
        huge_packet.time = current_time + i * 0.2
        packets.append(huge_packet)
    
    # Сохраняем пакеты
    output_dir = os.path.dirname(output_file)
    if output_dir and not os.path.exists(output_dir):
        os.makedirs(output_dir, exist_ok=True)
    
    wrpcap(output_file, packets)
    print(f"✅ Подозрительный трафик сохранен: {output_file} ({len(packets)} пакетов)")


def generate_mixed_traffic(output_file="data/mixed_traffic.pcap"):
    """
    Генерирует смешанный трафик (нормальный + подозрительный) для тестирования.
    
    Args:
        output_file: Путь к выходному PCAP файлу
    """
    print(f"🔀 Генерация смешанного трафика...")
    
    # Генерируем оба типа трафика отдельно
    normal_file = "data/normal_traffic_temp.pcap"
    suspicious_file = "data/suspicious_traffic_temp.pcap"
    
    generate_normal_traffic(normal_file, num_flows=30)
    generate_suspicious_traffic(suspicious_file)
    
    # Читаем оба файла и объединяем
    from scapy.all import rdpcap
    
    normal_packets = rdpcap(normal_file)
    suspicious_packets = rdpcap(suspicious_file)
    
    # Смешиваем пакеты по времени
    all_packets = list(normal_packets) + list(suspicious_packets)
    
    # Сортируем по времени
    all_packets.sort(key=lambda p: float(p.time))
    
    # Сохраняем смешанный трафик
    output_dir = os.path.dirname(output_file)
    if output_dir and not os.path.exists(output_dir):
        os.makedirs(output_dir, exist_ok=True)
    
    wrpcap(output_file, all_packets)
    
    # Удаляем временные файлы
    if os.path.exists(normal_file):
        os.remove(normal_file)
    if os.path.exists(suspicious_file):
        os.remove(suspicious_file)
    
    print(f"✅ Смешанный трафик сохранен: {output_file} ({len(all_packets)} пакетов)")


def main():
    """Основная функция для генерации всех типов трафика."""
    print("=" * 60)
    print("🚀 Генерация тестовых PCAP файлов")
    print("=" * 60)
    
    # Создаем директорию data, если её нет
    os.makedirs("data", exist_ok=True)
    
    # Генерируем нормальный трафик
    generate_normal_traffic("data/normal_traffic.pcap", num_flows=50)
    print()
    
    # Генерируем подозрительный трафик
    generate_suspicious_traffic("data/suspicious_traffic.pcap")
    print()
    
    # Генерируем смешанный трафик
    generate_mixed_traffic("data/mixed_traffic.pcap")
    print()
    
    print("=" * 60)
    print("✅ Генерация завершена!")
    print("=" * 60)
    print("\nСозданные файлы:")
    print("  📄 data/normal_traffic.pcap - нормальный трафик")
    print("  📄 data/suspicious_traffic.pcap - подозрительный трафик")
    print("  📄 data/mixed_traffic.pcap - смешанный трафик для тестирования")


if __name__ == "__main__":
    main()

