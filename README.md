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

```
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
│   │   └── phishing_data.csv
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
```


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
  - **`phishing_model.pkl`**: Trained machine learning model.

- **`reports/`**: Documentation and reports.

- **`requirements.txt`**: Python dependencies.

- **`setup.py`**: Package setup script.

- **`run_pipeline.py`**: Script to execute ML pipelines.

- **`run_app.py`**: Script to start the Flask application.

- **`Dockerfile`**: Docker configuration for containerization.

- **`.gitignore`**: Specifies files and directories to ignore in Git.

- **`README.md`**: Project documentation.



# Phishing Domain Classifier 

### Project Objective

* The purpose of this project is to build a website which classifies a domain either phishing or legitimate applying Machine Learning methodologies.


### Methods Used

* Data Wrangling
* Data Visualization
* Machine Learning
* Hyperparameter Tunning
* Predictive Modeling


### Algorithm Used

- Machine Learning: 
  - Extra Trees Classifier


### Technologies and Packages Used

* Python, Jupyter Notebook, Numpy
* Pandas, SciPy, Sklearn
* LazyPredict, GridSearch, Matplotlib
* Seaborn, Flask, BeautifulSoup


### Project Description

* Motivation:

  - 
  
  
* Data and Scope:

  - The dataset is downloaded from [`UCI Machine Learning Repository`](https://archive.ics.uci.edu/dataset/327/phishing+websites) donated by R. Mohammad and L. McCluskey in 2015. It's not defined how they collected the data but the features are well documented. The data size is around 10000 rows with 31 features and no missing values. Whenever a user request to classify a website, we will process the URL, extract public information in Whois, PhishTank, from the actual website string and other APIs.
  
  
* Methodology Approach:

  - Data Preprocessing:

  Upon receiving the website URL, we separate the URL's subdomain, domain, and public suffix, using the Public Suffix List (PSL) with tldextract. Then we make a request to check if the URL is accesible and any redirections. If everything is okay, we start extracting information from whois, API's and the URL string. Based on a set of rules documented by R. Mohammad and L. McCluskey, we create a list of features consisting of -1 (Phishing), 0 (Suspicious) and 1 (Legitimate). 
  
  - Algorithm: 

  During the [`Exploratory Data Analysis`](https://github.com/SwattyX/phishing-domain-classifier/blob/dev/notebooks/phishing_classifier_eda.ipynb) we used LazyClassifier from LazyPredict to determine the best fit model to our data. In this case, Extra Trees Classifier has the best score across all metrics. It's an ensembre learning method similar to Random Forest but it stands out in efficiency by spliting at random during training (unlike Random Forest which use the best split based on a criterion) and less chance of being too fine-tuned to the trainning data. 

  
### Results:

* Initial Results:

  Our model achieved an **accuracy of 98%**, demonstrating a high level of effectiveness in distinguishing between phishing and legitimate websites, raising questions about potential **overfitting** and its generalizability to unseen data. 

  In the following table, you may observe the performance results from our ensemble model. 

  | **Metric**        | **Value** |
  |-------------------|-----------|
  | **Accuracy**      | 0.98      |
  | **Precision**     | 0.98      |
  | **Recall**        | 0.98      |
  | **F1-Score**      | 0.98      |
  | **ROC-AUC Score** | 0.98      |
  
  Confusion Matrix

  - True Negatives (TN): 951 – Legitimate websites correctly identified.
  - False Positives (FP): 29 – Legitimate websites incorrectly classified as phishing.
  - False Negatives (FN): 21 – Phishing websites missed by the model.
  - True Positives (TP): 1,210 – Phishing websites correctly identified.


  There is some implications in our confusion matrix:
  - Low False Positives and Negatives: Indicates that the model rarely misclassifies legitimate websites as phishing (FP) and only misses a small number of phishing websites (FN).
  - Balanced Errors: The misclassification rates are similarly low for both classes, suggesting balanced performance.


  After testing with unseen data, it turns out our model 



* Final Results:



### Discussion:
  Los datos estan obsoletos


## Potential Issues

1. Bias
    - In the data we used to train our Naive Bayes classifier, a lot of the posts were discussing about the same stock, GME. This can cause some degree of bias as the words in those posts have a higher chance to relate to each other.
    - Although our ticker extraction algorithm is very accurate, sometimes the ticker identified for a given post is still inaccurate. This can also cause bias as then the computed growth percentage (label) would not be relevant for the associated post.
2. Lack of data
    - From around 40 000 posts, we filtered and cleaned it down to 1141 data points. Although these remaining 1141 posts we used to train the model were of good quality due to all the filtering we did, it is still a small quantity. We believe we may get even better results by acquiring more data, which was very difficult due to API limitations.


## Closing thoughts











- **High Accuracy:** Achieves up to 99% accuracy in detecting phishing websites.
- **Balanced Performance:** Maintains high precision, recall, and F1-scores across classes.
- **Robust Generalization:** Performs consistently on both test and completely unseen datasets.
- **Comprehensive Evaluation:** Utilizes multiple metrics to assess model performance thoroughly.
- **Efficient Training:** Optimized using GridSearchCV with Stratified K-Fold Cross-Validation.




  - Based on the related marketing research, it presents that **UserReviews** is the most influential factor for users to install the apps from Google PlayStore. However, there are something interesting when visualizing with EDA. For instance, I find out that rating score grows higher when the size of the app becomes smaller. That is to say, even though the average app rating is around 4.2 which is quite high, developers can still work on the **SIZE** issue to get better rating scores. 
  
  - In addition, since the type of social entertainments and games are the most popular apps above all, developers can focus on those developments. According to the results of sentimental analysis, it is obvious that most users have positive attitudes toward **Game, Health & Fitness and Travle & Local apps**.   
  
  - Furthermore, I can distinguish that **Linear Regression** model is robust and persuasive because R-squared is around 85%. Also, **Category, Type and Content Rating** are the three top influential factors in this model and they all have positive relations toward **Rating** factor. 
  
  - Moreover, the accuracy of **Random Forest Classification** model is around 76% which is a little bit lower than the Linear Regression model, but the results still remain strong and convincing since **Reviews and Size** are the top two meaningful factors from the results. On the other hand, **Price and Type** are less important in this classification analysis. 
  
  - In general, it is hard and unfair to say which model has a better performance since their **accuracies are pretty high**. Therefore, developers should choose wisely depending on their own purposes when applying the data with different kinds of machine learning models. 

Metric  Value
Accuracy: 0.98
Precision:  0.98
Recall: 0.98
F1-Score: 0.98
ROC-AUC Score:  0.98
  