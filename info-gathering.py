import os
import nmap
import openai

# Replace with your OpenAI API key
openai.api_key = '### your Key ###'

def scan_ip(ip_address):
    # Initialize the nmap scanner
    nm = nmap.PortScanner()

    # Perform the scan
    scan_data = nm.scan(ip_address, arguments='-sV -O')

    # Extract relevant data
    host_info = {
        'hostname': nm[ip_address].hostname(),
        'state': nm[ip_address].state(),
        'open_ports': [],
        'os': scan_data['scan'][ip_address].get('osmatch', [])
    }

    for proto in nm[ip_address].all_protocols():
        lport = nm[ip_address][proto].keys()
        for port in lport:
            service_info = nm[ip_address][proto][port]
            host_info['open_ports'].append({
                'port': port,
                'name': service_info['name'],
                'product': service_info.get('product', ''),
                'version': service_info.get('version', ''),
                'extrainfo': service_info.get('extrainfo', '')
            })

    return host_info

def generate_security_report(host_info):
    # Prepare the prompt for OpenAI
    prompt = f"""
    Analyze the following scan results and provide recommendations for mitigating security risks:

    Hostname: {host_info['hostname']}
    State: {host_info['state']}
    OS Information: {host_info['os']}

    Open Ports:
    """
    for port in host_info['open_ports']:
        prompt += f"\nPort: {port['port']}, Service: {port['name']}, Product: {port['product']}, Version: {port['version']}, Extra Info: {port['extrainfo']}"

    # Query OpenAI API using GPT-4-turbo
    response = openai.ChatCompletion.create(
        model="gpt-4o-2024-05-13",
        messages=[
            {"role": "system", "content": "You are a security expert."},
            {"role": "user", "content": prompt}
        ],
        max_tokens=4000
    )

    return response.choices[0].message['content'].strip()

def save_report(ip_address, report):
    filename = f"{ip_address}.txt"
    with open(filename, 'w') as report_file:
        report_file.write(report)
    print(f"Security report saved as {filename}")

def main():
    ip_address = input("Enter the IP address to scan: ")
    host_info = scan_ip(ip_address)

    # Display scan results
    print("\nScan Results:")
    print(f"Hostname: {host_info['hostname']}")
    print(f"State: {host_info['state']}")
    print(f"Open Ports: {', '.join([str(port['port']) for port in host_info['open_ports']])}")

    # Generate security report
    security_report = generate_security_report(host_info)

    # Save the report to a txt file
    save_report(ip_address, security_report)

if __name__ == "__main__":
    main()