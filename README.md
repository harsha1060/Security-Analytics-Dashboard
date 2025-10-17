**🛡️ SECURITY & ANALYTICS DASHBOARD**
=====================================

This project is a powerful, Python-based tool that provides a security and analytics overview for any website. It processes your web server's log data, transforming raw information into clear, actionable insights that can help you understand your website and secure it.

### **How This Project Can Help You**

-   **Monitor Website Operations:** Gain a clear understanding of your site's operational health by analyzing visitor traffic and identifying common HTTP status codes, allowing you to quickly spot issues like broken links (404s).

-   **Enhance Security Posture:** Proactively detect and analyze suspicious activity, such as vulnerability scanning. The tool identifies IP addresses that are probing your site for weaknesses by looking for high volumes of error codes.

-   **Audit External Security:** The project performs a live audit of a target website to report on crucial security elements, including missing HTTP security headers and open network ports. These checks are vital for ensuring your site is protected against common cyber threats.

-   **Understand Traffic Patterns:** Gain insight into where your website traffic originates from, which is a key component of a comprehensive security and analytics overview.

### **Getting Started**

#### **Prerequisites**

To use this tool, you'll need:

-   **Python 3.x**

-   **Your website's log file**: The project is configured to read a file named `access_logs.tsv`. Make sure your log file is in the **Combined Log Format** and rename it to `access_logs.tsv`.

-   **GeoIP Database**: Download the free `GeoLite2-City.mmdb` database from the [MaxMind website](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data). This is required for the visitor country analysis.

-   **Project Dependencies**: The required Python libraries are listed in `requirements.txt`.

#### **Setup and Installation**

1.  **Download the project files** or clone this repository.

2.  **Navigate to the project directory** in your terminal.

3.  **Install the required libraries** by running this command in your terminal:

    Bash

    ```
    pip install -r requirements.txt

    ```

4.  **Place your log file and the GeoLite2-City.mmdb file** in the project's root directory.

### **Usage**

Follow these steps in your terminal to process your logs and run the dashboard:

1.  **Set up the database**: This command creates a new, empty database file for your log data.

    Bash

    ```
    python database.py

    ```

2.  **Analyze your log data**: This script will read your log file and store all the data in the database.

    Bash

    ```
    python parse_logs.py

    ```

3.  **Start the dashboard**: Run the Flask application to view your security and analytics report.

    Bash

    ```
    python app.py

    ```

4.  **View the report**: Open your web browser and navigate to the local URL provided in the terminal (usually `http://127.0.0.1:5000`).

### **Contributing**

Contributions, issues, and feature requests are welcome!

### **License**

This project is licensed under the MIT License.
