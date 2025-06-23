import os
import numpy as np
from tensorflow.keras.models import load_model
import joblib
from ..models import RFParameters, PredictedParameters
from django.utils import timezone
import pandas as pd

# Get the absolute path to the current directory
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ML_MODELS_DIR = os.path.join(BASE_DIR, 'ml_models')

# Paths to the model and scaler
MODEL_PATH = os.path.join(ML_MODELS_DIR, 'prediction.keras')
SCALER_PATH = os.path.join(ML_MODELS_DIR, 'scaler.pkl')

# Load the model and scaler
try:
    model = load_model(MODEL_PATH)
    scaler = joblib.load(SCALER_PATH)
    print(f"Successfully loaded model from {MODEL_PATH}")
    print(f"Successfully loaded scaler from {SCALER_PATH}")
except Exception as e:
    print(f"Error loading model or scaler: {e}")
    raise


def preprocess_data(data, window_size=10):
    """Smooth and scale the data."""
    # Convert QuerySet to DataFrame
    df = pd.DataFrame(list(data.values('rsrp', 'rsrq', 'sinr')))
    
    # Apply moving average to smooth the data
    df = df.rolling(window=3, min_periods=1).mean()

    # Ensure enough data points
    if len(df) < window_size:
        return None

    features = df[['rsrp', 'rsrq', 'sinr']].values
    scaled_features = scaler.transform(features)
    return scaled_features[-window_size:].reshape((1, window_size, 3))

def validate_predictions(predictions):
    """Validate predictions to ensure they fall within realistic ranges."""
    valid_ranges = {'RSRP': (-140, -44), 'RSRQ': (-19.5, -3), 'SINR': (-20, 30)}
    noise_factors = {'RSRP': 0.5, 'RSRQ': 0.2, 'SINR': 0.3}

    validated_predictions = predictions.copy()
    for i, feature in enumerate(valid_ranges.keys()):
        min_val, max_val = valid_ranges[feature]
        noise = np.random.normal(0, noise_factors[feature], size=predictions[:, i].shape)
        validated_predictions[:, i] = np.clip(predictions[:, i] + noise, min_val, max_val)
    return validated_predictions

# def predict_and_save(lte_type, window_size=10):
#     """Fetch data from RFParameters, predict, validate, and save to PredictedParameters."""
#     data = RFParameters.objects.filter(lte_type=lte_type).order_by('-timestamp')[:window_size]
#     if data.count() < window_size:
#         print(f"Not enough data points for {lte_type}")
#         return

#     # Preprocess data
#     input_data = preprocess_data(data, window_size)
#     if input_data is None:
#         print(f"Insufficient data after preprocessing for {lte_type}")
#         return

#     # Perform prediction
#     prediction = model.predict(input_data, verbose=0)
#     unscaled_prediction = scaler.inverse_transform(prediction)

#     # Combine with last actual values for better accuracy
#     last_values = np.array([[data[0].rsrp, data[0].rsrq, data[0].sinr]])
#     weighted_prediction = 0.7 * last_values + 0.3 * unscaled_prediction

#     # Validate predictions
#     validated_prediction = validate_predictions(weighted_prediction)

#     # Save to database
#     timestamp = data.first().timestamp + timezone.timedelta(minutes=2)
#     PredictedParameters.objects.create(
#         timestamp=timestamp,
#         lte_type=lte_type,
#         predicted_rsrp=validated_prediction[0][0],
#         predicted_rsrq=validated_prediction[0][1],
#         predicted_sinr=validated_prediction[0][2],
#     )
#     print(f"Prediction saved for {lte_type}: RSRP={validated_prediction[0][0]}, RSRQ={validated_prediction[0][1]}, SINR={validated_prediction[0][2]}")


def predict_and_save(lte_type, window_size=10):
    print(f"Running prediction for {lte_type}")
    data = RFParameters.objects.filter(lte_type=lte_type).order_by('-timestamp')[:window_size]
    if data.count() < window_size:
        print(f"Not enough data points for {lte_type}")
        return

    # Preprocess data
    input_data = preprocess_data(data, window_size)
    if input_data is None:
        print(f"Insufficient data after preprocessing for {lte_type}")
        return

    # Perform prediction
    prediction = model.predict(input_data, verbose=0)
    unscaled_prediction = scaler.inverse_transform(prediction)

    # Combine with last actual values for better accuracy
    last_values = np.array([[data[0].rsrp, data[0].rsrq, data[0].sinr]])
    weighted_prediction = 0.7 * last_values + 0.3 * unscaled_prediction

    # Save to database
    timestamp = data.first().timestamp + timezone.timedelta(minutes=2)
    PredictedParameters.objects.create(
        timestamp=timestamp,
        lte_type=lte_type,
        predicted_rsrp=weighted_prediction[0][0],
        predicted_rsrq=weighted_prediction[0][1],
        predicted_sinr=weighted_prediction[0][2],
    )
    print(f"Prediction saved for {lte_type}: RSRP={weighted_prediction[0][0]}, RSRQ={weighted_prediction[0][1]}, SINR={weighted_prediction[0][2]}")
