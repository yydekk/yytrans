#!/usr/bin/env python3
"""
Простой скрипт для анализа PCAP файла.
Использование: python analyze_pcap.py <путь_к_pcap_файлу> [--model <путь_к_модели>] [--dashboard]
"""

import sys
import os
import argparse

# Добавляем src в путь для импорта модулей
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from traffic_analyzer import analyze_traffic


def main():
    parser = argparse.ArgumentParser(
        description='Анализ PCAP файла и обнаружение аномалий в сетевом трафике',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Примеры использования:
  python analyze_pcap.py my_traffic.pcap
  python analyze_pcap.py my_traffic.pcap --model models/anomaly_detector.pkl
  python analyze_pcap.py my_traffic.pcap --dashboard
  python analyze_pcap.py my_traffic.pcap --model models/anomaly_detector.pkl --dashboard
        """
    )
    
    parser.add_argument(
        'pcap_file',
        help='Путь к PCAP файлу для анализа'
    )
    
    parser.add_argument(
        '--model',
        '-m',
        default=None,
        help='Путь к обученной модели (опционально). Если не указан, используется базовая эвристика.'
    )
    
    parser.add_argument(
        '--output',
        '-o',
        default='data/analysis_results.csv',
        help='Путь к файлу для сохранения результатов (по умолчанию: data/analysis_results.csv)'
    )
    
    parser.add_argument(
        '--dashboard',
        '-d',
        action='store_true',
        help='Запустить веб-дашборд после анализа'
    )
    
    args = parser.parse_args()
    
    # Проверяем существование PCAP файла
    if not os.path.exists(args.pcap_file):
        print(f"❌ Ошибка: PCAP файл не найден: {args.pcap_file}")
        print(f"   Убедитесь, что файл существует и путь указан правильно.")
        sys.exit(1)
    
    # Проверяем модель, если указана
    if args.model and not os.path.exists(args.model):
        print(f"⚠️  Предупреждение: Модель не найдена: {args.model}")
        print(f"   Будет использована базовая эвристика для обнаружения аномалий.")
        args.model = None
    
    # Запускаем анализ
    try:
        print("\n" + "="*70)
        print("🚀 ЗАПУСК АНАЛИЗА PCAP ФАЙЛА")
        print("="*70)
        
        stats = analyze_traffic(
            pcap_file=args.pcap_file,
            model_path=args.model,
            output_csv=args.output
        )
        
        if stats:
            print("\n" + "="*70)
            print("✅ АНАЛИЗ ЗАВЕРШЕН УСПЕШНО!")
            print("="*70)
            print(f"📄 Результаты сохранены в: {stats['output_file']}")
            print(f"📊 Обнаружено аномалий: {stats['num_anomalies']} из {stats['total_flows']} потоков")
            print(f"📈 Процент аномалий: {stats['anomaly_percentage']:.2f}%")
            
            if args.dashboard:
                print("\n" + "="*70)
                print("🌐 ЗАПУСК ВЕБ-ДАШБОРДА")
                print("="*70)
                print("📊 Откройте браузер и перейдите по адресу: http://localhost:5000")
                print("⏹️  Для остановки дашборда нажмите Ctrl+C")
                print("="*70 + "\n")
                
                # Импортируем и запускаем дашборд
                import subprocess
                dashboard_path = os.path.join(os.path.dirname(__file__), 'dashboard', 'app.py')
                subprocess.run([sys.executable, dashboard_path])
        else:
            print("\n❌ Анализ завершился с ошибками")
            sys.exit(1)
            
    except Exception as e:
        print(f"\n❌ Ошибка при анализе: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()

