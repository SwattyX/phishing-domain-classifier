from sklearn.ensemble import ExtraTreesClassifier
import os

class Config:
    DEBUG = False
    DATA_PATH = 'data/processed'
    RAW_DATA_PATH = 'data/raw/phishing_data.arff'
    #MODEL_PATH = 'models/phishing_model.pkl'
    MODEL_PATH = os.path.join(os.path.dirname(__file__), '../models/phishing_model.pkl')
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
