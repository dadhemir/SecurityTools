import os
from dotenv import load_dotenv
import requests

# Load environment variables
load_dotenv()

# Get API key from environment variables
API_KEY = os.getenv('ALIENVAULT_API_KEY')

if not API_KEY:
    raise ValueError("Missing ALIENVAULT_API_KEY. Please check your .env file.")

def search_pulses(query, limit=10):
    """
    Search AlienVault OTX pulses for a specific query
    """
    url = 'https://otx.alienvault.com/api/v1/search/pulses'

    params = {
        'q': query,
        'limit': limit
    }

    headers = {
        'X-OTX-API-KEY': API_KEY
    }

    try:
        response = requests.get(url, headers=headers, params=params)
        response.raise_for_status()  # Raise an exception for bad status codes
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"Error making request: {e}")
        return None

def main():
    # Get search query from user
    query = input("Enter your search term (e.g., malware name, service name CVE, domain): ")

    # Get optional limit from user
    try:
        limit = int(input("Enter number of results to return (default 10): ") or 10)
    except ValueError:
        print("Invalid input. Using default limit of 10.")
        limit = 10

    # Search pulses
    print(f"\nSearching for: {query}")
    print("=" * 50)

    pulses = search_pulses(query, limit)

    if pulses and 'results' in pulses:
        for pulse in pulses['results']:
            print(f"\nPulse name: {pulse['name']}")
            print(f"Tags: {', '.join(pulse['tags'])}")
            print(f"Created: {pulse['created']}")
            print("-" * 50)
    else:
        print("No results found or an error occurred.")

if __name__ == "__main__":
    main()
