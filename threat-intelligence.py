import requests

api_key = '####'
url = 'https://otx.alienvault.com/api/v1/search/pulses'

# Query parameters: search for "Slack"
params = {
    'q': 'AWS',
    'limit': 10  # Limit the number of results
}

headers = {
    'X-OTX-API-KEY': api_key
}

response = requests.get(url, headers=headers, params=params)
pulses = response.json()

# Print the pulse names and indicators
for pulse in pulses['results']:
    print(f"Pulse name: {pulse['name']}")
    print(f"Tags: {pulse['tags']}")
    #print(f"Indicators: {pulse['indicators']}")
