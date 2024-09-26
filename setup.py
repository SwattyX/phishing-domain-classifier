from setuptools import find_packages, setup

setup(
    name='phishing_domain_classifier',
    version='0.1.0',
    description='A machine learning project to detect phishing websites',
    author='SwattyX',
    author_email='randolphrogersja@gmail.com',
    packages=find_packages(),
    include_package_data=True,
    install_requires=[
        'Flask',
        'joblib',
        'numpy',
        'pandas',
        'scikit-learn',
        'requests',
    ],
    entry_points={
        'console_scripts': [
            'phishing_domain_classifier=run_app',
        ],
    },
)