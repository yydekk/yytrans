"""
Модуль для обнаружения аномалий в сетевом трафике с помощью ML моделей.
"""

import pickle
import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    confusion_matrix, roc_auc_score
)
import os


class AnomalyDetector:
    """
    Класс для обнаружения аномалий в сетевом трафике.
    Использует Isolation Forest для unsupervised anomaly detection.
    """
    
    def __init__(self, contamination=0.1, random_state=42):
        """
        Инициализирует детектор аномалий.
        
        Args:
            contamination: Ожидаемая доля аномалий в данных (0.0-0.5)
            random_state: Seed для воспроизводимости результатов
        """
        self.model = IsolationForest(
            contamination=contamination,
            random_state=random_state,
            n_estimators=100
        )
        self.is_trained = False
        self.feature_columns = None  # Сохраняем названия признаков для предсказания
    
    def train_model(self, csv_file):
        """
        Обучает модель на нормальном трафике из CSV файла.
        
        Args:
            csv_file: Путь к CSV файлу с признаками трафика
        """
        if not os.path.exists(csv_file):
            raise FileNotFoundError(f"CSV файл не найден: {csv_file}")
        
        print(f"📚 Загрузка данных для обучения: {csv_file}")
        df = pd.read_csv(csv_file)
        
        # Проверяем наличие необходимых столбцов
        required_columns = [
            'packet_count', 'total_bytes', 'duration', 'avg_speed',
            'syn_count', 'ack_count', 'fin_count', 'rst_count',
            'protocol', 'src_port', 'dst_port', 'unique_ips'
        ]
        
        missing_columns = [col for col in required_columns if col not in df.columns]
        if missing_columns:
            raise ValueError(f"Отсутствуют необходимые столбцы: {missing_columns}")
        
        # Фильтруем только нормальный трафик (is_anomaly=0)
        if 'is_anomaly' in df.columns:
            normal_traffic = df[df['is_anomaly'] == 0].copy()
            print(f"   Нормальный трафик: {len(normal_traffic)} записей")
            print(f"   Аномальный трафик (игнорируется): {len(df) - len(normal_traffic)} записей")
        else:
            normal_traffic = df.copy()
            print(f"   Используются все данные: {len(normal_traffic)} записей")
        
        if len(normal_traffic) == 0:
            raise ValueError("Нет нормального трафика для обучения модели!")
        
        # Подготавливаем признаки для обучения
        # Исключаем нечисловые столбцы и метки
        feature_cols = [col for col in required_columns if col in normal_traffic.columns]
        
        # Обрабатываем протокол (преобразуем в числовой)
        if 'protocol' in normal_traffic.columns:
            protocol_mapping = {'TCP': 0, 'UDP': 1, 'ICMP': 2, 'OTHER': 3}
            normal_traffic = normal_traffic.copy()
            normal_traffic['protocol_encoded'] = normal_traffic['protocol'].map(
                lambda x: protocol_mapping.get(x, 3)
            )
            feature_cols.remove('protocol')
            feature_cols.append('protocol_encoded')
        
        # Извлекаем признаки
        X_train = normal_traffic[feature_cols].values
        
        # Обучаем модель
        print(f"🔧 Обучение Isolation Forest на {len(X_train)} образцах...")
        self.model.fit(X_train)
        self.is_trained = True
        self.feature_columns = feature_cols
        
        print(f"✅ Модель успешно обучена!")
        print(f"   Использовано признаков: {len(feature_cols)}")
        print(f"   Contamination: {self.model.contamination}")
    
    def _prepare_features(self, features):
        """
        Подготавливает признаки для предсказания (конвертирует DataFrame в массив).
        
        Args:
            features: DataFrame или массив с признаками
        
        Returns:
            numpy array: Подготовленные признаки
        """
        if isinstance(features, pd.DataFrame):
            # Используем сохраненные названия столбцов или все числовые столбцы
            if self.feature_columns:
                # Проверяем наличие всех необходимых столбцов
                missing_cols = [col for col in self.feature_columns if col not in features.columns]
                if missing_cols:
                    # Если нет protocol_encoded, но есть protocol, конвертируем
                    if 'protocol' in features.columns and 'protocol_encoded' not in features.columns:
                        protocol_mapping = {'TCP': 0, 'UDP': 1, 'ICMP': 2, 'OTHER': 3}
                        features = features.copy()
                        features['protocol_encoded'] = features['protocol'].map(
                            lambda x: protocol_mapping.get(x, 3)
                        )
                        missing_cols = [col for col in self.feature_columns if col not in features.columns]
                    
                    if missing_cols:
                        raise ValueError(f"Отсутствуют столбцы: {missing_cols}")
                
                X = features[self.feature_columns].values
            else:
                # Если модель не обучена, используем все числовые столбцы
                numeric_cols = features.select_dtypes(include=[np.number]).columns.tolist()
                # Исключаем is_anomaly если есть
                if 'is_anomaly' in numeric_cols:
                    numeric_cols.remove('is_anomaly')
                X = features[numeric_cols].values
        else:
            X = np.array(features)
        
        return X
    
    def predict(self, features):
        """
        Предсказывает аномалии для новых данных.
        
        Args:
            features: DataFrame или массив с признаками трафика
        
        Returns:
            array: Массив предсказаний (-1 для аномалий, 1 для нормального трафика)
        """
        if not self.is_trained:
            raise ValueError("Модель не обучена. Сначала вызовите train_model().")
        
        X = self._prepare_features(features)
        predictions = self.model.predict(X)
        return predictions
    
    def predict_anomaly_scores(self, features):
        """
        Возвращает anomaly scores для данных.
        
        Args:
            features: DataFrame или массив с признаками трафика
        
        Returns:
            array: Массив anomaly scores (меньше 0 = аномалия)
        """
        if not self.is_trained:
            raise ValueError("Модель не обучена. Сначала вызовите train_model().")
        
        X = self._prepare_features(features)
        scores = self.model.score_samples(X)
        return scores
    
    def predict_proba(self, features):
        """
        Возвращает вероятности аномалий (для совместимости с метриками).
        Использует decision_function для получения оценок.
        
        Args:
            features: DataFrame или массив с признаками трафика
        
        Returns:
            array: Массив вероятностей (чем меньше значение, тем выше вероятность аномалии)
        """
        if not self.is_trained:
            raise ValueError("Модель не обучена. Сначала вызовите train_model().")
        
        X = self._prepare_features(features)
        # decision_function возвращает отрицательные значения для аномалий
        decision_scores = self.model.decision_function(X)
        # Нормализуем к диапазону [0, 1] для использования в ROC-AUC
        # Меньшие значения = большая вероятность аномалии
        min_score = decision_scores.min()
        max_score = decision_scores.max()
        if max_score - min_score > 0:
            normalized = (decision_scores - min_score) / (max_score - min_score)
            # Инвертируем: меньшие значения = большая вероятность аномалии
            proba_anomaly = 1 - normalized
        else:
            proba_anomaly = np.zeros_like(decision_scores)
        
        return proba_anomaly
    
    def save_model(self, model_path):
        """
        Сохраняет обученную модель в файл.
        
        Args:
            model_path: Путь к файлу для сохранения модели
        """
        if not self.is_trained:
            raise ValueError("Модель не обучена. Сначала вызовите train_model().")
        
        # Создаем директорию, если её нет
        output_dir = os.path.dirname(model_path)
        if output_dir and not os.path.exists(output_dir):
            os.makedirs(output_dir, exist_ok=True)
        
        model_data = {
            'model': self.model,
            'feature_columns': self.feature_columns,
            'is_trained': self.is_trained
        }
        
        with open(model_path, 'wb') as f:
            pickle.dump(model_data, f)
        
        print(f"💾 Модель сохранена: {model_path}")
    
    def load_model(self, model_path):
        """
        Загружает обученную модель из файла.
        
        Args:
            model_path: Путь к файлу с моделью
        """
        if not os.path.exists(model_path):
            raise FileNotFoundError(f"Файл модели не найден: {model_path}")
        
        with open(model_path, 'rb') as f:
            model_data = pickle.load(f)
        
        # Поддержка старого формата (только модель) и нового (словарь)
        if isinstance(model_data, dict):
            self.model = model_data['model']
            self.feature_columns = model_data.get('feature_columns')
            self.is_trained = model_data.get('is_trained', True)
        else:
            self.model = model_data
            self.is_trained = True
        
        print(f"📂 Модель загружена: {model_path}")


def evaluate_model(test_csv, model):
    """
    Оценивает качество модели на тестовых данных.
    
    Args:
        test_csv: Путь к CSV файлу с тестовыми данными
        model: Обученная модель AnomalyDetector
    
    Returns:
        dict: Метрики качества (accuracy, precision, recall, f1, confusion_matrix, roc_auc)
    """
    if not model.is_trained:
        raise ValueError("Модель не обучена. Сначала обучите модель.")
    
    print(f"📊 Оценка модели на тестовых данных: {test_csv}")
    
    # Загружаем тестовые данные
    df = pd.read_csv(test_csv)
    
    # Проверяем наличие меток
    if 'is_anomaly' not in df.columns:
        raise ValueError("В тестовых данных отсутствует столбец 'is_anomaly'")
    
    # Получаем истинные метки (0 = нормальный, 1 = аномальный)
    y_true = df['is_anomaly'].values
    
    # Получаем предсказания модели (-1 = аномалия, 1 = нормальный)
    y_pred = model.predict(df)
    
    # Преобразуем предсказания в формат 0/1 (0 = нормальный, 1 = аномальный)
    # Isolation Forest: -1 = аномалия, 1 = нормальный
    y_pred_binary = (y_pred == -1).astype(int)
    
    # Вычисляем метрики
    accuracy = accuracy_score(y_true, y_pred_binary)
    precision = precision_score(y_true, y_pred_binary, zero_division=0)
    recall = recall_score(y_true, y_pred_binary, zero_division=0)
    f1 = f1_score(y_true, y_pred_binary, zero_division=0)
    cm = confusion_matrix(y_true, y_pred_binary)
    
    # ROC-AUC: используем decision_function для получения оценок
    try:
        # Получаем вероятности аномалий
        y_scores = model.predict_proba(df)
        roc_auc = roc_auc_score(y_true, y_scores)
    except Exception as e:
        print(f"⚠️  Не удалось вычислить ROC-AUC: {e}")
        roc_auc = None
    
    # Выводим результаты
    print(f"\n{'='*60}")
    print(f"📈 Результаты оценки модели:")
    print(f"{'='*60}")
    print(f"Accuracy:  {accuracy:.4f}")
    print(f"Precision: {precision:.4f}")
    print(f"Recall:    {recall:.4f}")
    print(f"F1-score:  {f1:.4f}")
    if roc_auc is not None:
        print(f"ROC-AUC:   {roc_auc:.4f}")
    print(f"\nConfusion Matrix:")
    print(f"                Predicted")
    print(f"              Normal  Anomaly")
    print(f"Actual Normal    {cm[0][0]:4d}    {cm[0][1]:4d}")
    print(f"       Anomaly   {cm[1][0]:4d}    {cm[1][1]:4d}")
    print(f"{'='*60}\n")
    
    # Возвращаем метрики
    metrics = {
        'accuracy': accuracy,
        'precision': precision,
        'recall': recall,
        'f1_score': f1,
        'confusion_matrix': cm,
        'roc_auc': roc_auc,
        'y_true': y_true,
        'y_pred': y_pred_binary,
        'y_scores': y_scores if roc_auc is not None else None
    }
    
    return metrics


if __name__ == "__main__":
    # Пример использования
    import sys
    
    if len(sys.argv) < 3:
        print("Использование:")
        print("  Обучение: python anomaly_detector.py train <train_csv> [model_path]")
        print("  Оценка:   python anomaly_detector.py evaluate <test_csv> <model_path>")
        sys.exit(1)
    
    command = sys.argv[1]
    
    if command == "train":
        train_csv = sys.argv[2]
        model_path = sys.argv[3] if len(sys.argv) > 3 else "models/anomaly_detector.pkl"
        
        detector = AnomalyDetector(contamination=0.1)
        detector.train_model(train_csv)
        detector.save_model(model_path)
    
    elif command == "evaluate":
        if len(sys.argv) < 4:
            print("Ошибка: для оценки нужны test_csv и model_path")
            sys.exit(1)
        
        test_csv = sys.argv[2]
        model_path = sys.argv[3]
        
        detector = AnomalyDetector()
        detector.load_model(model_path)
        metrics = evaluate_model(test_csv, detector)
    
    else:
        print(f"Неизвестная команда: {command}")
        sys.exit(1)
