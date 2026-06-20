FROM python:3.11-slim

# Install system dependencies (nmap is needed for discovery)
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy requirements and install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application modules
COPY cisco_crawler.py parser.py report_generator.py oui_lookup.py ./
COPY oui.txt* ./

# Ensure standard operational folders exist
RUN mkdir raw_logs backups deliverables

# Set entry point
ENTRYPOINT ["python3", "cisco_crawler.py"]
