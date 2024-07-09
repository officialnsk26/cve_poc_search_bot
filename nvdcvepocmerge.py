import requests
from datetime import datetime, timezone

# Function to fetch CVEs for a specific day
def fetch_cves(date):
    url = "https://poc-in-github.motikan2010.net/api/v1/"
    response = requests.get(url)
    if response.status_code == 200:
        cves = response.json()["pocs"]
        filtered_cves = [cve for cve in cves if cve["inserted_at"].startswith(date)]
        return filtered_cves
    else:
        print("Failed to fetch CVEs")
        return []

# Function to fetch detailed CVE information from NVD
def fetch_cve_details(cve_id):
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
    response = requests.get(url)
    if response.status_code == 200:
        return response.json()
    else:
        print(f"Failed to fetch details for CVE ID {cve_id}, Status Code: {response.status_code}")
        return None

def create_combined_cve_info_message(poc_cve, cve_details):
    message = "\n---------------------------------\n"
    if 'vulnerabilities' in cve_details and cve_details['vulnerabilities']:
        vulnerability = cve_details['vulnerabilities'][0]['cve']

        message += f"\n**CVE Information:**\n"
        message += f"\n🔍**CVE ID:** {vulnerability['id']}\n"
        message += f"\n🗓️**Published Date:** {vulnerability['published']}\n"
        message += f"\n✏️**Last Modified Date:** {vulnerability['lastModified']}\n"

        # Extract and display the description
        description = next((desc['value'] for desc in vulnerability['descriptions'] if desc['lang'] == 'en'), None)
        if description:
            message += f"\n📝**Description:** {description}\n"
        else:
            message += "📝**Description:** Not available\n"

        # Extract and display CVSS scores and severity
        if 'metrics' in vulnerability:
            message += create_cvss_scores_message(vulnerability['metrics'])

        # Extract and display CWE ID
        if 'weaknesses' in vulnerability:
            message += create_cwe_ids_message(vulnerability['weaknesses'])
            message += f"🌐\nMore details: https://nvd.nist.gov/vuln/detail/{vulnerability['id']}\n"

        # Display POC CVE details
        message += "\n**POC CVE Information:**\n"
        message += f"\n📓 **POC Description:** {poc_cve['description']}\n"
        message += f"\n🔓 **CVE Name:** {poc_cve['name']}\n"
        message += f"\n📓 **POC Vuln Description:** {poc_cve['vuln_description']}\n"
        message += f"\n🟢 **POC Owner:** {poc_cve['owner']}\n"
        message += f"\nℹ️ **Repository Name:** {poc_cve['full_name']}\n"
        message += f"\n📅 **POC Created At:** {poc_cve['created_at']}\n"
        message += f"\n📅 **POC Updated At:** {poc_cve['updated_at']}\n"
        message += f"\n📅 **POC Pushed At:** {poc_cve['pushed_at']}\n"
        message += f"\n📣 **POC URL:** {poc_cve['html_url']}\n"

        # Displaying the NVD search URL for direct access
        message += "--------------------------------------------------------------------------------------\n"

    else:
        message += "No other CVE POC's found in the provided data.\n"
        message += "--------------------------------------------------------------------------------------\n"
    
    return message

def create_cvss_scores_message(metrics):
    message = ""
    if 'cvssMetricV31' in metrics:
        cvss_v31 = metrics['cvssMetricV31'][0]['cvssData']
        message += f"📊 **CVSS 3.1 Score:** {cvss_v31['baseScore']} (Severity: {cvss_v31['baseSeverity']})\n"
    else:
        message += "📊 **CVSS 3.1 Score:** Not available\n"

    if 'cvssMetricV2' in metrics:
        cvss_v2 = metrics['cvssMetricV2'][0]['cvssData']
        severity_v2 = calculate_cvss_v2_severity(cvss_v2['baseScore'])
        message += f"📊 **CVSS 2.0 Score:** {cvss_v2['baseScore']} (Severity: {severity_v2})\n"
    else:
        message += "📊 **CVSS 2.0 Score:** Not available\n"
    
    return message

def calculate_cvss_v2_severity(score):
    if score < 4.0:
        return "LOW"
    elif score < 7.0:
        return "MEDIUM"
    else:
        return "HIGH"

def create_cwe_ids_message(weaknesses):
    cwe_ids = [desc['value'] for weakness in weaknesses for desc in weakness['description']]
    if cwe_ids:
        return f"**CWE ID(s):** {', '.join(cwe_ids)}\n"
    else:
        return "**CWE ID(s):** No CWE data available.\n"

# Function to send a message to Microsoft Teams via webhook URL
def send_teams_message(webhook_url, message):
    payload = {
        "text": message
    }
    response = requests.post(webhook_url, json=payload)
    if response.status_code != 200:
        print("Failed to send message to Teams")
    else:
        print("Message sent successfully")

# Set the date to fetch CVEs for (format: YYYY-MM-DD)
date_to_fetch = datetime.now(timezone.utc).strftime("%Y-%m-%d")

# Fetch CVEs for the specified date
cves = fetch_cves(date_to_fetch)

if cves:
    # Webhook URL for Microsoft Teams
    teams_webhook_url = "Your Teams Webhook URL"

    # Prepare message with CVE details
    message = f"New CVE POC has been discovered on {date_to_fetch}:\n\n"

    for poc_cve in cves:
        # Fetch detailed CVE information from NVD
        cve_details = fetch_cve_details(poc_cve['cve_id'])
        if cve_details:
            message += create_combined_cve_info_message(poc_cve, cve_details)

    # Send message to Teams
    send_teams_message(teams_webhook_url, message)
else:
    print("No CVE POC's reported for today")
