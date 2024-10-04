import re

# Step 1: Define Log Parsing Function
def parse_log_line(line):
    log_pattern = re.compile(
        r'(?P<ip_address>\S+) \S+ \S+ \[(?P<date_time>[^\]]+)\] '
        r'"(?P<request_method>\S+) (?P<request_path>\S+) \S+" '
        r'(?P<status_code>\d+) \S+'
    )
    match = log_pattern.match(line)
    if match:
        return match.groupdict()
    return None

# Step 2: Analyze Log for Suspicious Activities
def analyze_log_file(file_path):
    with open(file_path, 'r') as file:
        failed_logins = {}
        for line in file:
            parsed_line = parse_log_line(line)
            if parsed_line and parsed_line['status_code'] in ['401', '403']:
                ip_address = parsed_line['ip_address']
                failed_logins[ip_address] = failed_logins.get(ip_address, 0) + 1
        
        # Identify suspicious IPs based on threshold
        threshold = 5  # Example threshold
        suspicious_ips = {ip: count for ip, count in failed_logins.items() if count > threshold}
        return suspicious_ips

# Step 3: User Interface for Log Analysis
if __name__ == "__main__":
    log_file_path = input("Enter the path to the log file: ")
    suspicious_activities = analyze_log_file(log_file_path)
    
    if suspicious_activities:
        print("Suspicious IP addresses and their failed login counts:")
        for ip, count in suspicious_activities.items():
            print(f"{ip}: {count}")
    else:
        print("No suspicious activities detected based on the given criteria.")
