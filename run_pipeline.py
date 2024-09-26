from src.feature_pipeline import load_data, clean_data, preprocess_data
from src.model_pipeline import train_model
from src.utils import setup_logging
from src.config import Config
import logging

def main():
    setup_logging()
    logging.info("Starting the ML pipeline.")
    
    # Feature Pipeline
    df = load_data(Config.RAW_DATA_PATH)
    df = clean_data(df)
    X, y = preprocess_data(df)
        
    # Model Pipeline
    model = train_model(X, y)
    logging.info("ML pipeline completed successfully.")

if __name__ == "__main__":
    main()