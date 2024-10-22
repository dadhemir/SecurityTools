import requests
from googlesearch import search
import sys

# Set up your API keys and domain
HIBP_API_KEY = "###"
DOMAIN = "tudominio.com"

# Function to check Have I Been Pwned (HIBP) for domain breaches
def check_hibp(domain):
    url = f"https://haveibeenpwned.com/api/v3/breaches?domain={domain}"
    headers = {
        'hibp-api-key': HIBP_API_KEY,
        'User-Agent': 'Python script'
    }
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            return response.json()
        elif response.status_code == 404:
            return []
        else:
            print(f"Error: {response.status_code}")
            return None
    except Exception as e:
        print(f"Failed to connect to HIBP: {e}")
        return None

# Function to search Pastebin for mentions of the domain
def check_pastebin(domain):
    search_url = f"https://pastebin.com/search?q={domain}"
    try:
        response = requests.get(search_url)
        if response.status_code == 200:
            if domain in response.text:
                print(f"Possible data leaks found on Pastebin for {domain}")
            else:
                print(f"No mentions found on Pastebin for {domain}")
        else:
            print(f"Error fetching data from Pastebin: {response.status_code}")
    except Exception as e:
        print(f"Failed to connect to Pastebin: {e}")

# Function to perform Google Dorking
def google_dork(domain):
    queries = [
        f'site:pastebin.com intext:"{domain}"',
        f'site:github.com intext:"{domain} password"',
        f'filetype:xls OR filetype:csv "{domain}"'
    ]
    print("Google Dorking Results:")
    for query in queries:
        print(f"Searching for: {query}")
        try:
            results = search(query, num_results=5)
            for result in results:
                print(result)
        except Exception as e:
            print(f"Google search failed: {e}")

# Main function to run all checks
def main():
    print(f"Checking data leaks for domain: {DOMAIN}")
    # HIBP Check
    hibp_results = check_hibp(DOMAIN)
    if hibp_results is not None:
        if hibp_results:
            print("Have I Been Pwned Results:")
            for breach in hibp_results:
                print(f"- {breach['Name']}: {breach['Description']}")
        else:
            print(f"No breaches found for {DOMAIN} on HIBP.")
    # Pastebin Check
    #check_pastebin(DOMAIN)
    # Google Dorking Check
    #google_dork(DOMAIN)

if __name__ == "__main__":
    main()
