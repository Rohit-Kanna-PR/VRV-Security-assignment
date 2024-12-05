import csv
import argparse
from collections import Counter, defaultdict

def parse_log_file(log_file):
    ip_counter = Counter()
    endpoint_counter = Counter()
    failed_logins = defaultdict(int)

    try:
        with open(log_file, 'r') as file:
            for line in file:
                parts = line.split()
                if len(parts) < 9:
                    continue
                
                ip = parts[0]
                endpoint = parts[6]
                status_code = parts[8]
                
                ip_counter[ip] += 1
                endpoint_counter[endpoint] += 1
                
                if status_code == '401':
                    failed_logins[ip] += 1

    except FileNotFoundError:
        print(f"Error: File '{log_file}' not found.")
        return Counter(), Counter(), defaultdict(int)

    return ip_counter, endpoint_counter, failed_logins


def save_to_csv(filename, ip_counts, most_accessed, suspicious_activities):
    with open(filename, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["IP Address", "Request Count"])
        for ip, count in ip_counts.items():
            writer.writerow([ip, count])
        writer.writerow([])
        writer.writerow(["Most Frequently Accessed Endpoint"])
        writer.writerow(["Endpoint", "Access Count"])
        writer.writerow([most_accessed[0], most_accessed[1]])
        writer.writerow([])
        writer.writerow(["Suspicious Activity Detected"])
        writer.writerow(["IP Address", "Failed Login Count"])
        for ip, count in suspicious_activities.items():
            writer.writerow([ip, count])


def main():
    parser = argparse.ArgumentParser(description="Log Analysis Script")
    parser.add_argument("log_file", help="Path to the log file")
    parser.add_argument("-t", "--threshold", type=int, default=10,
                        help="Failed login attempts threshold (default: 10)")
    args = parser.parse_args()

    log_file = args.log_file
    threshold = args.threshold

    ip_counts, endpoint_counts, failed_logins = parse_log_file(log_file)
    most_accessed_endpoint = endpoint_counts.most_common(1)[0] if endpoint_counts else ("N/A", 0)
    suspicious_ips = {ip: count for ip, count in failed_logins.items() if count > threshold}

    print("\nRequests per IP Address:")
    print(f"{'IP Address':<20} {'Request Count':<15}")
    for ip, count in ip_counts.most_common():
        print(f"{ip:<20} {count:<15}")
    
    print("\nMost Frequently Accessed Endpoint:")
    print(f"{most_accessed_endpoint[0]} (Accessed {most_accessed_endpoint[1]} times)")
    
    print("\nSuspicious Activity Detected:")
    print(f"{'IP Address':<20} {'Failed Login Attempts':<20}")
    for ip, count in suspicious_ips.items():
        print(f"{ip:<20} {count:<20}")
    
    save_to_csv("log_analysis_results.csv", ip_counts, most_accessed_endpoint, suspicious_ips)
    print("\nResults saved to log_analysis_results.csv")


if __name__ == "__main__":
    main()
