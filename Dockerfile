# Use a lightweight Python base image
FROM python:3.9-slim

# Set the working directory
WORKDIR /app

# Create logs directory
RUN mkdir -p /app/logs

# Install system dependencies for PyQt5 and GUI rendering
RUN apt-get update && apt-get install -y \
    libx11-6 \
    libxext-dev \
    libxrender1 \
    libxtst6 \
    libxi6 \
    libpcap-dev \
    python3-pyqt5 \
    x11-apps \
    net-tools \
    iputils-ping \
    libgl1-mesa-glx \ 
    && rm -rf /var/lib/apt/lists/*

# Copy the requirements file into the container
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy the src directory into the container
COPY . .

# Set the command to run the application
CMD ["python", "src/gui.py"]
