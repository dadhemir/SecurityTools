import requests

# Set up your HIBP API key
HIBP_API_KEY = "###"

# Function to check if an email is part of a data breach using HIBP
def check_email(email):
    url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}?truncateResponse=false"
    headers = {
        'hibp-api-key': HIBP_API_KEY,
        'User-Agent': 'Python script',
        'Accept': 'application/json'
    }
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            return response.json()  # Returns a list of breaches
        elif response.status_code == 404:
            return []  # No breaches found
        else:
            print(f"Error: {response.status_code} - {response.text}")
            return None
    except Exception as e:
        print(f"Failed to connect to HIBP: {e}")
        return None

# Main function to get user input and check email
def main():
    email = input("Enter the email address to check: ")
    results = check_email(email)

    if results is not None:
        if results:
            print(f"Breaches found for {email}:")
            for breach in results:
                print(f"- {breach['Name']}: {breach['DataClasses']}")
        else:
            print(f"No breaches found for {email}.")
    else:
        print("Failed to retrieve data. Please check your API key and internet connection.")

if __name__ == "__main__":
    main()