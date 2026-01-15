# Как использовать проект для анализа PCAP файлов

## Быстрый старт

### 1. Установка зависимостей

```bash
pip install -r requirements.txt
```

### 2. Анализ вашего PCAP файла

Самый простой способ - использовать скрипт `analyze_pcap.py`:

```bash
python analyze_pcap.py ваш_файл.pcap
```

### 3. Просмотр результатов

После анализа результаты сохраняются в `data/analysis_results.csv`. 

Для просмотра в веб-интерфейсе запустите дашборд:

```bash
python analyze_pcap.py ваш_файл.pcap --dashboard
```

Или запустите дашборд отдельно:

```bash
cd dashboard
python app.py
```

Затем откройте браузер: http://localhost:5000

## Параметры запуска

### Базовый анализ (без ML модели)

```bash
python analyze_pcap.py traffic.pcap
```

Использует простую эвристику для обнаружения аномалий:
- Много RST флагов
- Порт-сканирование (много SYN без завершения соединений)
- Большое количество пакетов
- Необычные комбинации портов

### Анализ с ML моделью

Если у вас есть обученная модель:

```bash
python analyze_pcap.py traffic.pcap --model models/anomaly_detector.pkl
```

### Указать путь для результатов

```bash
python analyze_pcap.py traffic.pcap --output my_results.csv
```

### Запустить дашборд автоматически

```bash
python analyze_pcap.py traffic.pcap --dashboard
```

## Примеры использования

### Пример 1: Простой анализ

```bash
python analyze_pcap.py /path/to/my_traffic.pcap
```

Результат:
- Файл `data/analysis_results.csv` с результатами анализа
- Статистика в консоли

### Пример 2: Анализ с моделью и дашбордом

```bash
python analyze_pcap.py /path/to/my_traffic.pcap --model models/anomaly_detector.pkl --dashboard
```

Результат:
- Анализ с использованием ML модели
- Автоматический запуск веб-дашборда

### Пример 3: Анализ с сохранением в другое место

```bash
python analyze_pcap.py /path/to/my_traffic.pcap --output /tmp/results.csv
```

## Структура результатов

Результаты сохраняются в CSV файл со следующими столбцами:

- `timestamp` - временная метка потока
- `src_ip` - IP адрес источника
- `dst_ip` - IP адрес назначения
- `src_port` - порт источника
- `dst_port` - порт назначения
- `protocol` - протокол (TCP/UDP/ICMP)
- `packet_count` - количество пакетов в потоке
- `anomaly_score` - оценка аномалии (меньше 0 = аномалия)
- `is_anomaly` - флаг аномалии (0 = нормальный, 1 = аномалия)
- `alert_level` - уровень критичности (NORMAL, LOW, MEDIUM, HIGH, CRITICAL)

## Уровни критичности

- **CRITICAL** - Критичные аномалии, требующие немедленного внимания
- **HIGH** - Высокий уровень угрозы
- **MEDIUM** - Средний уровень угрозы
- **LOW** - Низкий уровень угрозы
- **NORMAL** - Нормальный трафик

## Обучение модели (опционально)

Если вы хотите использовать ML модель для более точного обнаружения аномалий:

1. Сгенерируйте тестовые данные:
```bash
python src/generate_test_traffic.py
```

2. Извлеките признаки:
```bash
python src/feature_extractor.py data/normal_traffic.pcap data/normal_features.csv 0
python src/feature_extractor.py data/suspicious_traffic.pcap data/suspicious_features.csv 1
```

3. Объедините данные и обучите модель:
```bash
python src/anomaly_detector.py train data/traffic_features.csv models/anomaly_detector.pkl
```

4. Используйте модель при анализе:
```bash
python analyze_pcap.py your_file.pcap --model models/anomaly_detector.pkl
```

## Устранение проблем

### Ошибка: "PCAP файл не найден"
- Убедитесь, что путь к файлу указан правильно
- Используйте абсолютный путь, если относительный не работает

### Ошибка: "Не удалось извлечь признаки"
- Проверьте, что PCAP файл не поврежден
- Убедитесь, что файл содержит сетевой трафик (не пустой)

### Ошибка импорта модулей
- Убедитесь, что вы находитесь в корневой директории проекта
- Проверьте, что все зависимости установлены: `pip install -r requirements.txt`

## Дополнительная информация

- Подробные примеры: см. `EXAMPLES.md`
- План развития проекта: см. `PROJECT_PLAN.md`
- Объяснение расчета рисков: см. `RISK_EXPLANATIONS.md`

