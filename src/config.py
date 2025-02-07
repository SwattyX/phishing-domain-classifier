from sklearn.ensemble import RandomForestClassifier
import os

class Config:
    DEBUG = False
    DATA_PATH = "data/processed"
    BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  
    RAW_DATA_PATH = os.path.join(BASE_DIR, "data", "raw", "phishing_data.csv")
    MODEL_PATH = os.path.join(BASE_DIR, "models", "phishing_model.pkl")
    MODELS = {
        "RandomForestClassifier": {
            "class": RandomForestClassifier,
            "params": {
                "class_weight": "balanced"}
        },
    }
    ACTIVE_MODEL = "RandomForestClassifier"
