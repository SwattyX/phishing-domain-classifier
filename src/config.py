from sklearn.ensemble import ExtraTreesClassifier
import os
import logging

class Config:
    DEBUG = False
    DATA_PATH = 'data/processed'
    BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  
    RAW_DATA_PATH = os.path.join(BASE_DIR, 'data', 'raw', 'phishing_data.csv')
    MODEL_PATH = os.path.join(BASE_DIR, 'models', 'phishing_model.pkl')
    MODELS = {
        'ExtraTreesClassifier': {
            'class': ExtraTreesClassifier,
            'params': {
                'bootstrap': False,
                'class_weight': 'balanced',
                'max_depth': None,
                'min_samples_leaf': 1,
                'min_samples_split': 5,
                'n_estimators': 200}
        },
    }
    ACTIVE_MODEL = 'ExtraTreesClassifier'
