# network_monitoring/services/predictor.py
from django.conf import settings
from django.utils import timezone
from ..models import RFParameters
import pandas as pd
import numpy as np
from tensorflow.keras.models import load_model
import joblib
import logging
import os

logger = logging.getLogger(__name__)

class NetworkPredictor:
    def __init__(self):
        self.model_path = os.path.join(settings.BASE_DIR, 'network_monitoring', 'ml_models', 'prediction.keras')
        self.scaler_path = os.path.join(settings.BASE_DIR, 'network_monitoring', 'ml_models', 'scaler.pkl')
        self.window_size = 10
        self._load_models()

    def _load_models(self):
        """Load ML model and scaler"""
        try:
            self.model = load_model(self.model_path)
            self.scaler = joblib.load(self.scaler_path)
            logger.info("Successfully loaded model and scaler")
        except Exception as e:
            logger.error(f"Error loading model or scaler: {e}")
            raise

    def get_recent_data(self, lte_type, window_size=10):
        """Fetch recent data from database"""
        try:
            data = RFParameters.objects.filter(
                lte_type=lte_type
            ).order_by('-timestamp')[:window_size]
            
            if len(data) < window_size:
                logger.warning(f"Insufficient data points for {lte_type}")
                return None

            df = pd.DataFrame(list(data.values()))
            return df
        except Exception as e:
            logger.error(f"Error fetching recent data: {e}")
            return None

    def preprocess_data(self, df):
        """Preprocess data for prediction"""
        try:
            features_df = pd.DataFrame({
                'RSRP': df['rsrp'],
                'RSRQ': df['rsrq'],
                'SNR': df['sinr']
            })
            
            # Apply moving average
            features_df = features_df.rolling(window=3, min_periods=1).mean()
            
            features = features_df[['RSRP', 'RSRQ', 'SNR']].values
            scaled_data = self.scaler.transform(features)
            
            return scaled_data.reshape((1, self.window_size, 3))
        except Exception as e:
            logger.error(f"Error preprocessing data: {e}")
            return None

    def validate_predictions(self, predictions):
        """Validate predictions are within acceptable ranges"""
        valid_ranges = {
            'RSRP': (-140, -44),
            'RSRQ': (-19.5, -3),
            'SNR': (-20, 30)
        }
        
        validated = np.clip(
            predictions,
            [valid_ranges['RSRP'][0], valid_ranges['RSRQ'][0], valid_ranges['SNR'][0]],
            [valid_ranges['RSRP'][1], valid_ranges['RSRQ'][1], valid_ranges['SNR'][1]]
        )
        
        # Add small random variation
        noise = np.random.normal(0, 0.1, validated.shape)
        return validated + noise

    def predict_next_values(self, lte_type):
        """Generate predictions for the next expected timestamp"""
        try:
            # Get recent data
            df = self.get_recent_data(lte_type, self.window_size)
            if df is None:
                return None

            # Get last actual timestamp and compute next expected timestamp
            last_actual_timestamp = df.iloc[0]['timestamp']
            next_timestamp = last_actual_timestamp + pd.Timedelta(minutes=2)

            # Preprocess data
            input_data = self.preprocess_data(df)
            if input_data is None:
                return None

            # Make prediction
            prediction = self.model.predict(input_data, verbose=0)
            unscaled_prediction = self.scaler.inverse_transform(prediction)
            
            # Get last actual values
            last_actual = df.iloc[0][['rsrp', 'rsrq', 'sinr']].values.reshape(1, -1)
            
            # Weight prediction with actual values
            weighted_prediction = 0.7 * last_actual + 0.3 * unscaled_prediction
            validated_prediction = self.validate_predictions(weighted_prediction)
            
            return {
                'timestamp': next_timestamp,
                'rsrp': round(float(validated_prediction[0, 0])),
                'rsrq': round(float(validated_prediction[0, 1])),
                'sinr': round(float(validated_prediction[0, 2]))
            }
        except Exception as e:
            logger.error(f"Error generating prediction: {e}")
            return None
