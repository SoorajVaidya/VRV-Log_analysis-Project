import pandas as pd
import re

# Configuration
LOG_FILE = 'sample.log' #sample log file
FAILED_LOGIN_THRESHOLD = 5  # maximum allowable failed login attempts for each IP

def parse_log_file(file_path):

    #reads the logfile and parses the required fields into the dataframe
    log_data = []
    ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'  #IP address pattern
    endpoint_pattern = r'\"(?:GET|POST|PUT|DELETE) (/\S*)' 
    status_code_pattern = r'\s(\d{3})\s'  

    with open(file_path, 'r') as file:
        for line in file:
            ip_match = re.search(ip_pattern, line)
            endpoint_match = re.search(endpoint_pattern, line)
            status_code_match = re.search(status_code_pattern, line)

            if ip_match and endpoint_match and status_code_match:
                log_data.append({
                    'IP': ip_match.group(),
                    'Endpoint': endpoint_match.group(1),
                    'StatusCode': status_code_match.group(1)
                })

    return pd.DataFrame(log_data)

#count the number of requests per IP address
def count_requests_per_ip(log_df):
    return log_df['IP'].value_counts()

#identifies the most frequent accessed endpoint
def identify_most_frequent_endpoint(log_df):
    return log_df['Endpoint'].value_counts().idxmax(), log_df['Endpoint'].value_counts().max()

#detects IPs with excessive failed login attempts 
def detect_suspicious_activity(log_df):
    failed_attempts = log_df[log_df['StatusCode'] == '401']
    failed_counts = failed_attempts['IP'].value_counts()
    return failed_counts[failed_counts > FAILED_LOGIN_THRESHOLD]

#saving the results to csv
def save_results_to_csv(ip_counts, most_frequent_endpoint, suspicious_ips):
    with pd.ExcelWriter('log_analysis_results.xlsx') as writer:
        ip_counts.to_frame(name='Request Count').to_excel(writer, sheet_name='Requests per IP')
        
        pd.DataFrame([{
            'Endpoint': most_frequent_endpoint[0],
            'Access Count': most_frequent_endpoint[1]
        }]).to_excel(writer, sheet_name='Most Accessed Endpoint', index=False)
        
        suspicious_ips.to_frame(name='Failed Login Count').to_excel(writer, sheet_name='Suspicious Activity')

def main():
    log_df = parse_log_file(LOG_FILE)
    #prints requests per IP,frequently accessed endpoint,suspicious activity message 
    # Count requests per IP
    ip_counts = count_requests_per_ip(log_df)
    print("\nRequests per IP:")
    print(ip_counts)

    # Identify the most frequently accessed endpoint
    most_frequent_endpoint = identify_most_frequent_endpoint(log_df)
    print("\nMost Frequently Accessed Endpoint:")
    print(f"{most_frequent_endpoint[0]} (Accessed {most_frequent_endpoint[1]} times)")

    # Detect suspicious activity
    suspicious_ips = detect_suspicious_activity(log_df)
    print("\nSuspicious Activity Detected:")
    print(suspicious_ips)

    # Save results of log to CSV
    save_results_to_csv(ip_counts, most_frequent_endpoint, suspicious_ips)
    print("\nResults saved to 'log_analysis_results.xlsx'")

if __name__ == "__main__":
    main()
