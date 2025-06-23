# network_monitoring/services/predictor.py
import numpy as np
from tensorflow.keras.models import load_model
import joblib
from ..models import RFParameters, PredictedParameters
from django.utils import timezone
import os

# model = load_model("prediction.keras")
# scaler = joblib.load("scaler.pkl")





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


def predict_and_save(lte_type, window_size=10):
    """Fetch data from RFParameters, predict, and save to PredictedParameters."""
    data = RFParameters.objects.filter(lte_type=lte_type).order_by('-timestamp')[:window_size]

    if data.count() < window_size:
        print(f"Not enough data points for {lte_type}")
        return

    # Prepare input data
    features = np.array([[item.rsrp, item.rsrq, item.sinr] for item in reversed(data)])
    scaled_data = scaler.transform(features)
    input_window = scaled_data.reshape((1, window_size, 3))

    # Perform prediction
    prediction = model.predict(input_window, verbose=0)
    unscaled_prediction = scaler.inverse_transform(prediction)[0]

    # Save prediction to the database
    timestamp = data.first().timestamp + timezone.timedelta(minutes=2)
    PredictedParameters.objects.create(
        timestamp=timestamp,
        lte_type=lte_type,
        predicted_rsrp=unscaled_prediction[0],
        predicted_rsrq=unscaled_prediction[1],
        predicted_sinr=unscaled_prediction[2],
    )
    print(f"Prediction saved for {lte_type}: RSRP={unscaled_prediction[0]}, RSRQ={unscaled_prediction[1]}, SINR={unscaled_prediction[2]}")
