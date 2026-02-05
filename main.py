import requests
import re
import csv
import json

# --- CONFIGURATION ---
API_KEY = '876c78b22667bc7e1354369ff3ae169a31f9f27d78ae1ec880941cfe4e52edb5191fd34c5dfbd89b'  
LOG_FILE = 'server_logs.txt'
OUTPUT_FILE = 'threat_report.csv'
ABUSE_DB_URL = 'https://api.abuseipdb.com/api/v2/check'


def extract_ips(log_file):
    """Reads a log file and uses Regex to find all IP addresses."""
    with open(log_file, 'r') as f:
        log_content = f.read()
    # Regex pattern for IPv4 addresses
    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    ips = re.findall(ip_pattern, log_content)
    return list(set(ips))  # Remove duplicates

def check_ip_reputation(ip):
    """Queries AbuseIPDB to check if an IP is malicious."""
    # Skip private IPs (like 192.168.x.x)
    if ip.startswith("192.168.") or ip.startswith("10.") or ip.startswith("127."):
        return None

    headers = {
        'Key': API_KEY,
        'Accept': 'application/json'
    }
    params = {
        'ipAddress': ip,
        'maxAgeInDays': 90
    }
    
    try:
        response = requests.get(ABUSE_DB_URL, headers=headers, params=params)
        return response.json()
    except Exception as e:
        print(f"Error checking {ip}: {e}")
        return None

def main():
    print(f"[*] Reading logs from {LOG_FILE}...")
    unique_ips = extract_ips(LOG_FILE)
    print(f"[*] Found {len(unique_ips)} unique IP addresses.")

    print("[*] Checking IPs against AbuseIPDB...")
    
    # Prepare CSV Output
    with open(OUTPUT_FILE, 'w', newline='') as csvfile:
        fieldnames = ['IP Address', 'Abuse Confidence Score', 'ISP', 'Country', 'Total Reports']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()

        for ip in unique_ips:
            result = check_ip_reputation(ip)
            
            if result and 'data' in result:
                data = result['data']
                score = data['abuseConfidenceScore']
                print(f" -> Checked {ip}: Score {score}%")
                
                # Write to CSV
                writer.writerow({
                    'IP Address': ip,
                    'Abuse Confidence Score': score,
                    'ISP': data['isp'],
                    'Country': data['countryCode'],
                    'Total Reports': data['totalReports']
                })
    
    print(f"\n[+] Analysis Complete! Report saved to '{OUTPUT_FILE}'")

if __name__ == "__main__":
    main()