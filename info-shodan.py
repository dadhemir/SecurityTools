import shodan
import requests

# Your Shodan API key
API_KEY = '### your Shodan Key ###'

# Initialize the Shodan API client
api = shodan.Shodan(API_KEY)

# Prompt the user to input the IP address
ip_address = input("Enter the public IP address you want to search: ")

# Output file path
output_file = f'shodan_{ip_address}_info.txt'

def get_cve_details(cve_id):
    """
    Fetches CVE details from a public CVE database.
    """
    url = f"https://cve.circl.lu/api/cve/{cve_id}"
    response = requests.get(url)
    if response.status_code == 200:
        return response.json()
    else:
        return None

try:
    # Perform the Shodan search
    host = api.host(ip_address)

    # Write the results to a text file
    with open(output_file, 'w') as file:
        file.write(f"IP: {host['ip_str']}\n")
        file.write(f"Organization: {host.get('org', 'N/A')}\n")
        file.write(f"Operating System: {host.get('os', 'N/A')}\n")

        file.write("\nOpen Ports:\n")
        for item in host['data']:
            file.write(f"Port: {item['port']}\n")
            file.write(f"Service: {item['product'] if 'product' in item else 'N/A'}\n")
            file.write(f"Banner: {item['data']}\n")
            file.write("-" * 40 + "\n")

        file.write("\nVulnerabilities:\n")
        for vuln in host.get('vulns', []):
            file.write(f"Vulnerability: {vuln}\n")
            cve_details = get_cve_details(vuln)
            if cve_details:
                file.write(f"  Summary: {cve_details.get('summary', 'No summary available')}\n")
                file.write(f"  Published Date: {cve_details.get('Published', 'N/A')}\n")
                file.write(f"  CVSS Score: {cve_details.get('cvss', 'N/A')}\n")
                file.write(f"  Recommendations: {cve_details.get('references', 'No recommendations available')}\n")
            else:
                file.write("  No additional CVE details found.\n")

    print(f"Results written to {output_file}")

except shodan.APIError as e:
    print(f"Error: {e}")