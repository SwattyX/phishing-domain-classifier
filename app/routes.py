from flask import Blueprint, render_template, request, jsonify
from src.feature_pipeline import FeatureExtractor, parse_features
from src.config import Config
import joblib
import numpy as np
import logging

# Blueprint for main routes
main = Blueprint('main', __name__)

# Load the trained model
model = joblib.load(Config.MODEL_PATH)

@main.route('/')
def index():
    return render_template('index.html')

@main.route('/predict', methods=['POST'])
def predict():
    try:
        data = request.get_json()
        if not data or 'url' not in data:
            return jsonify({'success': False, 'message': 'No URL provided.'}), 400
        url = data['url']
        
        # Preprocess the input data
        X_processed = FeatureExtractor(url).extract_all_features()
        features = parse_features(X_processed)

        # Make prediction
        prediction = model.predict(X_processed)
        probability = model.predict_proba(X_processed)  
        probability = np.max(probability)
        return jsonify({
            'success': True,
            'prediction': int(prediction[0]),
            'probability': probability,
            'features': features
        })

    except Exception as e:
        logging.error(f"Error during prediction: {e}")
        return jsonify({'success': False, 'message': 'Invalid URL.'}), 500