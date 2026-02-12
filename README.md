# Automated-Threat-Parser
Python tool for automating ip's reputation using the abuseipdb api.

#  Automated Threat Intelligence Parser

###  Project Overview
This tool automates the analysis of network logs by extracting IP addresses and cross-referencing them with **AbuseIPDB**, a global threat intelligence database. It helps SOC analysts quickly identify high-risk IPs without manual lookups.

### 🛠️ Features
* **Log Parsing:** Uses RegEx to extract IPv4 addresses from any text-based log file (SSH logs, Web Server logs, etc.).
* **API Integration:** Automates queries to the AbuseIPDB API v2.
* **Risk Scoring:** Filters out private IPs (192.168.x.x) and retrieves Abuse Confidence Scores, ISP info, and Country codes.
* **Reporting:** Exports a structured CSV report (`threat_report.csv`) for further analysis.

###  Usage
```python
# 1. Add your API Key in main.py
API_KEY = 'YOUR_KEY_HERE'

# 2. Run the script
python main.py
IP Address,Confidence Score,ISP,Country
118.25.6.39,12%,Tencent Cloud Computing,CN
178.128.157.6,0%,"DigitalOcean, LLC",US
45.227.255.255,0%,Okpay Investment Company,NL
