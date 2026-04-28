FROM python:3.11-slim

WORKDIR /app

# Install iptables
RUN apt-get update && \
    apt-get install -y iptables && \
    rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy all detector source files
COPY . .

# Default config path (can be overridden)
ENV CONFIG_PATH=/app/config.yaml

CMD ["python", "main.py"]

RUN mkdir -p /var/log/detector
