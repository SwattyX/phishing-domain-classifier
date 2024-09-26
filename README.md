# ML Classification Project with Flask Integration

![Project Logo](https://via.placeholder.com/150)

## Table of Contents

- [Introduction](#introduction)
- [Features](#features)
- [Project Structure](#project-structure)
- [Installation](#installation)
- [Usage](#usage)
  - [Running the Machine Learning Pipeline](#running-the-machine-learning-pipeline)
  - [Running the Flask Application](#running-the-flask-application)
- [Caching](#caching)
- [Testing](#testing)
- [Deployment](#deployment)
- [Contributing](#contributing)
- [License](#license)
- [Acknowledgements](#acknowledgements)

## Introduction

Welcome to the **ML Classification Project with Flask Integration**! This project demonstrates a robust machine learning workflow for classification tasks, seamlessly integrated into a Flask web application. Leveraging a **3 Pipeline Architecture**, the project ensures modularity, scalability, and maintainability, making it suitable for both development and production environments.

## Features

- **3 Pipeline Architecture**: 
  - **Data Pipeline**: Handles data ingestion, cleaning, and preprocessing.
  - **Feature Pipeline**: Manages feature engineering and selection.
  - **Model Pipeline**: Covers model training, validation, and deployment.
  
- **Flask Web Application**: Provides a user-friendly interface for inputting data and viewing predictions.
  
- **Caching with Flask-Caching**: Enhances performance by caching frequent predictions.
  
- **Modular Codebase**: Organized project structure promoting reusability and ease of maintenance.
  
- **Comprehensive Testing**: Ensures reliability through unit tests for each pipeline component and Flask routes.

## Project Structure

A well-organized project structure is crucial for managing complexity. Below is the recommended structure incorporating the **3 Pipeline Architecture** and Flask integration:

phishing_domain_classifier/
│
├── app/
│   ├── static/
│   │   ├── css/
│   │   │   └── styles.css
│   │   └── js/
│   │   │   └── script.css
│   ├── templates/
│   │   ├── index.html
│   ├── __init__.py
│   ├── routes.py
│
├── data/
│   ├── raw/
│   │   └── phishing_data.arff
│   ├── processed/
│   └── external/
│
├── notebooks/
│   └── phishing_classifier_eda.ipynb
│
├── src/
│   ├── __init__.py
│   ├── feature_pipeline.py
│   ├── inference_pipeline.py
│   ├── model_pipeline.py
│   ├── config.py
│   └── utils.py
│
├── models/
│   └── phishing_model.pkl/
│
├── reports/
│   ├── figures/
│   └── report.pdf
│
├── requirements.txt
├── setup.py
├── run_pipeline.py
├── run_app.py
├── Dockerfile
├── .gitignore
└── README.md



**Key Directories and Files:**

- **`app/`**: Contains Flask application files.
  - **`static/`**: Static assets like CSS and JavaScript.
  - **`templates/`**: HTML templates.
  - **`__init__.py`**: Initializes the Flask app and caching.
  - **`routes.py`**: Defines Flask routes and prediction logic.

- **`data/`**: Data storage.
  - **`raw/`**: Original, unprocessed data.
  - **`processed/`**: Cleaned and processed data.
  - **`external/`**: External datasets or resources.

- **`notebooks/`**: Jupyter notebooks for exploration and modeling.

- **`src/`**: Source code for ML pipelines.
  - **`feature_pipeline.py`**: Feature engineering and selection.
  - **`model_pipeline.py`**: Model training and evaluation.
  - **`inference_pipeline.py`**: Data inference for direct predict in console.
  - **`config.py`**: Configuration parameters.
  - **`utils.py`**: Utility functions.

- **`models/`**: Serialized models and pipelines.
  - **`phishing_classifier.pkl`**: Trained machine learning model.

- **`reports/`**: Documentation and reports.

- **`requirements.txt`**: Python dependencies.

- **`setup.py`**: Package setup script.

- **`run_pipeline.py`**: Script to execute ML pipelines.

- **`run_app.py`**: Script to start the Flask application.

- **`Dockerfile`**: Docker configuration for containerization.

- **`.gitignore`**: Specifies files and directories to ignore in Git.

- **`README.md`**: Project documentation.

