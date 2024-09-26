# Use a Python 3.11 slim image
FROM python:3.11-slim

# Set the working directory in the container
WORKDIR /

# Copy the requirements file and install dependencies
COPY requirements.txt requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application code
COPY . .

# Expose the port the app will run on
EXPOSE 8000

# Command to run the app
CMD ["python", "run_app.py"]