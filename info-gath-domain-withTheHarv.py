import socket
import shodan
import requests
import subprocess
from fpdf import FPDF

# API keys (replace with your actual keys)
SHODAN_API_KEY = '### your Key ###'
HIBP_API_KEY = '### your Key ###'

def get_ip_from_domain(domain):
    try:
        ip = socket.gethostbyname(domain)
        return ip
    except socket.gaierror:
        return None

def analyze_ip_with_shodan(ip):
    api = shodan.Shodan(SHODAN_API_KEY)
    try:
        results = api.host(ip)
        report = f"Shodan results for IP {ip}:\n"
        report += f"Organization: {results.get('org', 'N/A')}\n"
        report += f"Operating System: {results.get('os', 'N/A')}\n"

        vulnerabilities = results.get('vulns', [])
        if vulnerabilities:
            report += "CVEs found:\n"
            for cve in vulnerabilities:
                report += f"- {cve}\n"
        else:
            report += "No CVEs found.\n"
        return report
    except shodan.APIError as e:
        return f"Error: {e}\n"

def run_theharvester(domain):
    try:
        result = subprocess.run(['theHarvester', '-d', domain, '-b', 'all'], capture_output=True, text=True)
        return result.stdout
    except subprocess.CalledProcessError as e:
        return f"Error running theHarvester: {e}"

def check_hibp(domain):
    url = f"https://haveibeenpwned.com/api/v3/breaches?domain={domain}"
    headers = {
        'hibp-api-key': HIBP_API_KEY,
        'User-Agent': 'Python Script'
    }
    response = requests.get(url, headers=headers)
    report = ""
    if response.status_code == 200:
        breaches = response.json()
        if breaches:
            report += f"Breaches found for {domain}:\n"
            for breach in breaches:
                report += f"- {breach['Name']}: {breach['Description']}\n"
        else:
            report += f"No breaches found for {domain}\n"
    else:
        report += f"Error checking HIBP: {response.status_code}\n"
    return report

def export_to_pdf(domain, ip, shodan_report, harvester_report, hibp_report):
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=12)

    # Add domain information
    pdf.cell(200, 10, txt=f"Domain Analysis Report: {domain}", ln=True, align='C')
    pdf.cell(200, 10, txt=f"IP Address: {ip if ip else 'Not Resolved'}", ln=True)

    # Shodan report
    pdf.multi_cell(0, 10, txt="Shodan Analysis:")
    pdf.multi_cell(0, 10, txt=shodan_report)

    # HIBP report
    pdf.multi_cell(0, 10, txt="\nHave I Been Pwned Results:")
    pdf.multi_cell(0, 10, txt=hibp_report)

    # TheHarvester report
    pdf.multi_cell(0, 10, txt="\nTheHarvester Results:")
    pdf.multi_cell(0, 10, txt=harvester_report)

    # Save PDF
    pdf_file_name = f"{domain}_analysis_report.pdf"
    pdf.output(pdf_file_name)
    print(f"Report saved as {pdf_file_name}")

def main():
    domain = input("Enter a domain to analyze: ")

    ip = get_ip_from_domain(domain)
    if ip:
        print(f"IP address for {domain}: {ip}")
        shodan_report = analyze_ip_with_shodan(ip)
        print(shodan_report)
    else:
        print(f"Could not resolve IP for {domain}")
        shodan_report = "Could not perform Shodan analysis."

    print("\nChecking Have I Been Pwned...")
    hibp_report = check_hibp(domain)
    print(hibp_report)

    print("\nRunning theHarvester...")
    harvester_report = run_theharvester(domain)
    print(harvester_report)

    # Export to PDF
    export_to_pdf(domain, ip, shodan_report, harvester_report, hibp_report)

if __name__ == "__main__":
    main()