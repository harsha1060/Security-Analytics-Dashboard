# Use an official Python runtime as a parent image
FROM python:3.11-slim

# Install OpenSSH client (needed for the 'ssh' command in app.py)
RUN apt-get update && apt-get install -y openssh-client && rm -rf /var/lib/apt/lists/*

# Set the working directory in the container
WORKDIR /app

# Copy the requirements file into the container
COPY requirements.txt .

# Install any needed packages specified in requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of your application code
COPY . .

# Expose the port Flask runs on
EXPOSE 5000

# Command to run the application
CMD ["python", "app.py"]