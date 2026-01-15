from flask import Flask, render_template, request, jsonify, redirect, url_for
import pandas as pd
import os
import json
import uuid
import shutil
from datetime import datetime
from werkzeug.utils import secure_filename

app = Flask(__name__)

# Get the project root directory (one level up from dashboard/)
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(PROJECT_ROOT, "data")
UPLOADS_DIR = os.path.join(DATA_DIR, "uploads")
ANALYSES_DIR = os.path.join(DATA_DIR, "analyses")

# Ensure directories exist
os.makedirs(UPLOADS_DIR, exist_ok=True)
os.makedirs(ANALYSES_DIR, exist_ok=True)

# Index file to track all uploads
UPLOADS_INDEX = os.path.join(DATA_DIR, "uploads_index.json")

ALLOWED_EXTENSIONS = {'pcap', 'pcapng'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def load_uploads_index():
    if os.path.exists(UPLOADS_INDEX):
        with open(UPLOADS_INDEX, 'r', encoding='utf-8') as f:
            return json.load(f)
    return []

def save_uploads_index(index):
    with open(UPLOADS_INDEX, 'w', encoding='utf-8') as f:
        json.dump(index, f, ensure_ascii=False, indent=2)

def classify_anomaly_type(row):
    """
    Классифицирует тип аномалии на основе признаков потока.
    """
    packet_count = row.get('packet_count', 0)
    rst_count = row.get('rst_count', 0)
    syn_count = row.get('syn_count', 0)
    dst_port = row.get('dst_port', 0)
    src_port = row.get('src_port', 0)
    
    if packet_count > 500 and rst_count > 10:
        return "Подозрительные сессии"
    elif packet_count > 1000:
        return "DDoS"
    elif syn_count > 20 and packet_count < 50:
        return "Порт-сканирование"
    elif dst_port < 1024 and src_port > 49152:
        return "Необычные порты"
    else:
        return "Другое"


@app.route("/")
def index():
    """Главная страница со списком загруженных файлов."""
    uploads = load_uploads_index()
    # Sort by date descending
    uploads.sort(key=lambda x: x.get('upload_time', ''), reverse=True)
    return render_template("uploads.html", uploads=uploads)


@app.route("/upload", methods=['POST'])
def upload_file():
    """Загрузка нового PCAP файла."""
    if 'file' not in request.files:
        return jsonify({'error': 'Файл не выбран'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'Файл не выбран'}), 400
    
    if not allowed_file(file.filename):
        return jsonify({'error': 'Разрешены только .pcap и .pcapng файлы'}), 400
    
    # Generate unique ID for this upload
    upload_id = str(uuid.uuid4())[:8]
    original_filename = secure_filename(file.filename)
    
    # Create directory for this analysis
    analysis_dir = os.path.join(ANALYSES_DIR, upload_id)
    os.makedirs(analysis_dir, exist_ok=True)
    
    # Save the file
    pcap_path = os.path.join(analysis_dir, original_filename)
    file.save(pcap_path)
    
    # Run analysis
    try:
        import sys
        sys.path.insert(0, os.path.join(PROJECT_ROOT, 'src'))
        from traffic_analyzer import analyze_traffic
        
        results_csv = os.path.join(analysis_dir, 'analysis_results.csv')
        packets_json = os.path.join(analysis_dir, 'packets.json')
        
        # Run the analysis
        analyze_traffic(pcap_path, model_path=None, output_csv=results_csv)
        
        # Load results to get stats
        df = pd.read_csv(results_csv)
        total_flows = len(df)
        num_anomalies = len(df[df['is_anomaly'] == 1]) if 'is_anomaly' in df.columns else 0
        
        # Count by alert level
        critical = len(df[df['alert_level'] == 'CRITICAL']) if 'alert_level' in df.columns else 0
        high = len(df[df['alert_level'] == 'HIGH']) if 'alert_level' in df.columns else 0
        
        status = 'completed'
        error_msg = None
    except Exception as e:
        total_flows = 0
        num_anomalies = 0
        critical = 0
        high = 0
        status = 'error'
        error_msg = str(e)
    
    # Add to index
    uploads = load_uploads_index()
    uploads.append({
        'id': upload_id,
        'filename': original_filename,
        'upload_time': datetime.now().isoformat(),
        'status': status,
        'error': error_msg,
        'total_flows': total_flows,
        'anomalies': num_anomalies,
        'critical': critical,
        'high': high
    })
    save_uploads_index(uploads)
    
    return jsonify({'success': True, 'id': upload_id, 'redirect': f'/analysis/{upload_id}'})


@app.route("/analysis/<upload_id>")
def view_analysis(upload_id):
    """Просмотр результатов анализа конкретного файла."""
    uploads = load_uploads_index()
    upload_info = next((u for u in uploads if u['id'] == upload_id), None)
    
    if not upload_info:
        return "Анализ не найден", 404
    
    analysis_dir = os.path.join(ANALYSES_DIR, upload_id)
    data_file = os.path.join(analysis_dir, 'analysis_results.csv')
    packets_file = os.path.join(analysis_dir, 'packets.json')
    
    if not os.path.exists(data_file):
        return render_template("index.html", 
                             data=[], 
                             stats={}, 
                             top_ips=[], 
                             anomaly_types={},
                             has_data=False,
                             upload_info=upload_info,
                             upload_id=upload_id)
    
    df = pd.read_csv(data_file)
    
    # Конвертируем timestamp в datetime
    if 'timestamp' in df.columns:
        try:
            df['datetime'] = pd.to_datetime(df['timestamp'], unit='s', errors='coerce')
            if df['datetime'].isna().all():
                df['datetime'] = pd.to_datetime(df['timestamp'], errors='coerce')
        except:
            df['datetime'] = pd.to_datetime(df['timestamp'], errors='coerce')
    else:
        df['datetime'] = pd.NaT
    
    # Классифицируем типы аномалий
    if 'is_anomaly' in df.columns:
        anomalies_df = df[df['is_anomaly'] == 1].copy()
        if len(anomalies_df) > 0:
            anomalies_df['anomaly_type'] = anomalies_df.apply(classify_anomaly_type, axis=1)
        else:
            anomalies_df['anomaly_type'] = 'Другое'
    else:
        anomalies_df = pd.DataFrame()
        anomalies_df['anomaly_type'] = []
    
    data = df.to_dict(orient="records")
    
    total_flows = len(df)
    num_anomalies = len(df[df['is_anomaly'] == 1]) if 'is_anomaly' in df.columns else 0
    anomaly_percentage = (num_anomalies / total_flows * 100) if total_flows > 0 else 0
    
    if 'alert_level' in df.columns:
        critical = len(df[df['alert_level'] == 'CRITICAL'])
        high = len(df[df['alert_level'] == 'HIGH'])
        medium = len(df[df['alert_level'] == 'MEDIUM'])
        low = len(df[df['alert_level'] == 'LOW'])
        normal = len(df[df['alert_level'] == 'NORMAL'])
    else:
        critical = high = medium = low = normal = 0
    
    stats = {
        'total_flows': total_flows,
        'num_anomalies': num_anomalies,
        'anomaly_percentage': round(anomaly_percentage, 2),
        'critical': critical,
        'high': high,
        'medium': medium,
        'low': low,
        'normal': normal
    }
    
    top_ips = []
    if num_anomalies > 0 and 'src_ip' in df.columns and 'dst_ip' in df.columns:
        ip_counts = {}
        anomalies = df[df['is_anomaly'] == 1]
        for _, row in anomalies.iterrows():
            for ip in [row['src_ip'], row['dst_ip']]:
                ip_counts[ip] = ip_counts.get(ip, 0) + 1
        
        sorted_ips = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:10]
        top_ips = [{'ip': ip, 'count': count} for ip, count in sorted_ips]
    
    anomaly_types = {}
    if len(anomalies_df) > 0 and 'anomaly_type' in anomalies_df.columns:
        anomaly_types = anomalies_df['anomaly_type'].value_counts().to_dict()
    
    timeline_data = []
    
    return render_template("index.html", 
                         data=data, 
                         stats=stats, 
                         top_ips=top_ips,
                         anomaly_types=anomaly_types,
                         timeline_data=timeline_data,
                         has_data=len(df) > 0,
                         upload_info=upload_info,
                         upload_id=upload_id)


@app.route("/api/data/<upload_id>")
def api_data(upload_id):
    """API endpoint для получения данных с фильтрами."""
    analysis_dir = os.path.join(ANALYSES_DIR, upload_id)
    data_file = os.path.join(analysis_dir, 'analysis_results.csv')
    
    if not os.path.exists(data_file):
        return jsonify({"data": [], "stats": {}})
    
    df = pd.read_csv(data_file)
    
    alert_level = request.args.get('alert_level', '')
    ip_address = request.args.get('ip_address', '')
    
    if alert_level and alert_level != 'ALL':
        df = df[df['alert_level'] == alert_level]
    
    if ip_address:
        df = df[(df['src_ip'] == ip_address) | (df['dst_ip'] == ip_address)]
    
    data = df.to_dict(orient="records")
    
    total_flows = len(df)
    num_anomalies = len(df[df['is_anomaly'] == 1]) if 'is_anomaly' in df.columns else 0
    
    return jsonify({
        "data": data,
        "stats": {
            "total_flows": total_flows,
            "num_anomalies": num_anomalies
        }
    })


@app.route("/api/packets/<upload_id>")
def api_packets(upload_id):
    """API endpoint для просмотра пакетов."""
    analysis_dir = os.path.join(ANALYSES_DIR, upload_id)
    packets_file = os.path.join(analysis_dir, 'packets.json')
    
    if not os.path.exists(packets_file):
        return jsonify({"data": [], "total": 0})

    try:
        with open(packets_file, "r", encoding="utf-8") as f:
            packets = json.load(f)
    except Exception:
        return jsonify({"data": [], "total": 0})

    total = len(packets)

    try:
        start = int(request.args.get("start", 0))
        limit = int(request.args.get("limit", 200))
    except Exception:
        start, limit = 0, 200

    limit = max(1, min(limit, 500))
    start = max(0, start)

    sliced = packets[start:start + limit]

    return jsonify({"data": sliced, "total": total, "start": start, "limit": limit})


@app.route("/delete/<upload_id>", methods=['POST'])
def delete_analysis(upload_id):
    """Удаление анализа."""
    uploads = load_uploads_index()
    uploads = [u for u in uploads if u['id'] != upload_id]
    save_uploads_index(uploads)
    
    # Remove directory
    analysis_dir = os.path.join(ANALYSES_DIR, upload_id)
    if os.path.exists(analysis_dir):
        shutil.rmtree(analysis_dir)
    
    return jsonify({'success': True})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
