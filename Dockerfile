FROM python:3.11-slim

# Install OpenSSH client
RUN apt-get update && apt-get install -y openssh-client && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy requirements and install
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy all project files
COPY . .

# --- FIX FOR SSH KEY PERMISSIONS ---
# We create a secure directory, copy the key there, and restrict permissions
RUN mkdir -p /root/.ssh && \
    chmod 700 /root/.ssh

# We will use a script or a command change to handle the key at runtime
EXPOSE 5000

CMD ["sh", "-c", "cp /app/login.pem /root/login.pem && chmod 600 /root/login.pem && python app.py"]