import hashlib
import requests

def check_pwned_password(password):
    # Step 1: Hash the password using SHA1
    sha1_password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()

    # Step 2: Send only the first 5 characters of the SHA1 hash to the API
    prefix = sha1_password[:5]
    suffix = sha1_password[5:]

    # Step 3: Query the API
    url = f'https://api.pwnedpasswords.com/range/{prefix}'
    response = requests.get(url)

    # Step 4: Check if the suffix of our hash is in the response
    hashes = (line.split(':') for line in response.text.splitlines())
    for h, count in hashes:
        if h == suffix:
            return f'Password has been pwned {count} times!'

    return 'Password not found in the Pwned Passwords database.'

# Example usage:
password_to_check = 'platzi'
result = check_pwned_password(password_to_check)
print(result)