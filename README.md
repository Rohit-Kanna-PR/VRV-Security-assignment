# VRV-Security-assignment

This Python script analyzes web server log files to extract and analyze critical information. It uses argparse for command-line arguments, allowing dynamic configuration of the log file path and failed login thresholds. The script leverages Counter and defaultdict from the collections module for efficient data aggregation.

**Key Features:**

  **Requests per IP Address:** Counts and sorts the number of requests made by each IP address.
  
  **Most Accessed Endpoint:** Identifies the endpoint with the highest access count.
  
  **Suspicious Activity Detection:** Flags IPs with failed login attempts (HTTP status 401) exceeding a configurable threshold.
  
**Output:**

  Displays results in a clean terminal table.
  
  Saves analysis to a structured CSV file using the csv module.
  
  The script processes logs efficiently, ensuring scalability for large files. It handles invalid or empty logs gracefully, ensuring robustness. This modular and performance-optimized design adheres to Python best   practices, making it ideal for cybersecurity and log analysis tasks.
