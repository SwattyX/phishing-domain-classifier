import joblib
from src.config import Config
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix

def train_model(X, y):
    # Splitting the dataset into the Training set and Test set
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    # Get model class and params from config
    model_config = Config.MODELS[Config.ACTIVE_MODEL]
    model_class = model_config['class']
    model_params = model_config['params']

    # Instantiate the model dynamically
    model = model_class(**model_params)

    # Train the model
    model.fit(X_train, y_train)

    #Print used model
    print("Model: ",Config.ACTIVE_MODEL)

    # Save the trained model
    with open(Config.MODEL_PATH, 'wb') as f:
        joblib.dump(model, f)
    
    # Evaluate on the test set
    y_pred = model.predict(X_test)

    # Classification report and confusion matrix
    print("Classification report:\n", classification_report(y_test, y_pred))
    print("Confusion matrix:\n", confusion_matrix(y_test, y_pred))