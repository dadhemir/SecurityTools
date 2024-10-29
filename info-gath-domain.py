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
        report += f"Operating System: {results.get('os', 'N/A')}\n\n"

        vulnerabilities = results.get('vulns', [])
        if vulnerabilities:
            # Dictionary to store CVEs by severity
            severity_groups = {
                'CRITICAL': [],
                'HIGH': [],
                'MEDIUM': [],
                'LOW': [],
                'UNKNOWN': []
            }

            # Get details for each CVE and group them
            for cve in vulnerabilities:
                try:
                    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve}"
                    response = requests.get(url, headers={'User-Agent': 'Python Script'})

                    if response.status_code == 200:
                        data = response.json()
                        if data['vulnerabilities']:
                            vuln = data['vulnerabilities'][0]['cve']
                            metrics = vuln.get('metrics', {})

                            # Get CVSS data
                            if 'cvssMetricV31' in metrics:
                                cvss = metrics['cvssMetricV31'][0]
                            elif 'cvssMetricV30' in metrics:
                                cvss = metrics['cvssMetricV30'][0]
                            else:
                                severity_groups['UNKNOWN'].append((cve, 'N/A', 'No CVSS data available'))
                                continue

                            base_score = cvss['cvssData']['baseScore']
                            severity = cvss['cvssData']['baseSeverity']
                            description = vuln['descriptions'][0]['value']

                            severity_groups[severity].append((cve, base_score, description))
                    else:
                        severity_groups['UNKNOWN'].append((cve, 'N/A', 'Failed to fetch details'))

                except Exception as e:
                    severity_groups['UNKNOWN'].append((cve, 'N/A', f'Error: {str(e)}'))

            # Generate report grouped by severity
            report += "CVEs found (grouped by severity):\n"

            for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN']:
                cves = severity_groups[severity]
                if cves:
                    report += f"\n{severity} Severity Vulnerabilities:\n"
                    report += "=" * 50 + "\n"
                    for cve, score, desc in sorted(cves, key=lambda x: x[1] if isinstance(x[1], (int, float)) else -1, reverse=True):
                        report += f"  {cve}\n"
                        report += f"  Score: {score}\n"
                        report += f"  Description: {desc}\n\n"

        else:
            report += "No CVEs found.\n"
        return report
    except shodan.APIError as e:
        return f"Error: {e}\n"

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

def export_to_pdf(domain, ip, shodan_report, hibp_report):
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

    # Export to PDF
    export_to_pdf(domain, ip, shodan_report, hibp_report)

if __name__ == "__main__":
    main()