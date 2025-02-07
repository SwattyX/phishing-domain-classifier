import joblib
import numpy as np
from src.config import Config

# Load the trained model
model = joblib.load(Config.MODEL_PATH)

def predict(X_processed: list) -> tuple:
    try:
        prediction = model.predict(X_processed)
        probability = model.predict_proba(X_processed)  
        return (prediction,probability)
    except Exception as e:
           print(f"Error during prediction: {e}")