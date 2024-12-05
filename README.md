LOG ANALYSIS SCRIPT:
This project provides a Python script to analyze server log files and extract key insights, such as request counts per IP, most accessed endpoints, and potential suspicious activity.

Features:
*Count Requests per IP Address
Parses the log file to count the number of requests made by each IP address and displays them in descending order.

*Identify Most Accessed Endpoint
Extracts the endpoints from the log and identifies the most frequently accessed endpoint.

*Detect Suspicious Activity
Flags IPs with failed login attempts exceeding a configurable threshold (I have considered 5 attempts).

*Save Results
Outputs results to an Excel file (log_analysis_results.xlsx) with the following sheets:

--->Requests per IP: IP addresses and their request counts.
--->Most Accessed Endpoint: The endpoint and its access count.
--->Suspicious Activity: Suspicious IPs with failed login counts.
