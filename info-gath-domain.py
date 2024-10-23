import socket
import shodan
import requests
import subprocess
import json

# API keys (replace with your actual keys)
SHODAN_API_KEY = '###'
HIBP_API_KEY = '###'

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
      print(f"Shodan results for IP {ip}:")
      print(f"Organization: {results.get('org', 'N/A')}")
      print(f"Operating System: {results.get('os', 'N/A')}")

      vulnerabilities = results.get('vulns', [])
      if vulnerabilities:
          print("CVEs found:")
          for cve in vulnerabilities:
              print(f"- {cve}")
      else:
          print("No CVEs found.")
  except shodan.APIError as e:
      print(f"Error: {e}")

def run_theharvester(domain):
  try:
      result = subprocess.run(['theharvester', '-d', domain, '-b', 'all'], capture_output=True, text=True)
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
  if response.status_code == 200:
      breaches = response.json()
      if breaches:
          print(f"Breaches found for {domain}:")
          for breach in breaches:
              print(f"- {breach['Name']}: {breach['Description']}")
      else:
          print(f"No breaches found for {domain}")
  else:
      print(f"Error checking HIBP: {response.status_code}")

def main():
  domain = input("Enter a domain to analyze: ")

  ip = get_ip_from_domain(domain)
  if ip:
      print(f"IP address for {domain}: {ip}")
      analyze_ip_with_shodan(ip)
  else:
      print(f"Could not resolve IP for {domain}")

  print("\nRunning theHarvester...")
  harvester_results = run_theharvester(domain)
  print(harvester_results)

  print("\nChecking Have I Been Pwned...")
  check_hibp(domain)

if __name__ == "__main__":
  main()