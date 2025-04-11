# Use an official Python runtime as a parent image
FROM python:3.11-slim

# Set environment variables to prevent Python from writing pyc files and buffering stdout/stderr
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

# Set the working directory in the container
WORKDIR /app

# Install system dependencies that might be needed (e.g., for psycopg2 or hiredis)
# Optional: only include if specific C extensions need building
# RUN apt-get update && apt-get install -y --no-install-recommends gcc build-essential libpq-dev && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy the application code into the container
COPY main.py .
# Copy .env file if you use one for configuration (optional, depends on how you manage secrets)
# COPY .env .

# Make port 8000 available to the world outside this container
EXPOSE 8000

# Define the command to run your app using uvicorn
# Use 0.0.0.0 to ensure it's accessible from outside the container
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
