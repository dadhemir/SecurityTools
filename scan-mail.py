import openai
import email
from email.policy import default

# Set your OpenAI API key
openai.api_key = '### your Key ###'

def extract_eml_details(eml_file_path):
    with open(eml_file_path, 'r', encoding='utf-8') as f:
        msg = email.message_from_file(f, policy=default)

    email_details = {
        'from': msg['from'],
        'to': msg['to'],
        'subject': msg['subject'],
        'body': "",
        'html': ""
    }

    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            if content_type == 'text/plain':
                email_details['body'] = part.get_payload(decode=True).decode(part.get_content_charset(), errors='ignore')
            elif content_type == 'text/html':
                email_details['html'] = part.get_payload(decode=True).decode(part.get_content_charset(), errors='ignore')
    else:
        content_type = msg.get_content_type()
        if content_type == 'text/plain':
            email_details['body'] = msg.get_payload(decode=True).decode(msg.get_content_charset(), errors='ignore')
        elif content_type == 'text/html':
            email_details['html'] = msg.get_payload(decode=True).decode(msg.get_content_charset(), errors='ignore')

    return email_details

def review_email_with_gpt4(email_details):
    # Combine body and html for analysis
    content = email_details['body'] + "\n\n" + email_details['html']

    # Query GPT-4o for review
    response = openai.ChatCompletion.create(
        model="gpt-4o-2024-05-13",
        messages=[
            {"role": "system", "content": "You are a security expert tasked with identifying phishing emails."},
            {"role": "user", "content": f"Analyze the following email content and determine if it's phishing or legitimate:\n\n{content}"}
        ],
        max_tokens=2000,
        n=1,
        stop=None,
        temperature=0.5,
    )

    analysis = response['choices'][0]['message']['content'].strip()
    return analysis

def main(eml_file_path):
    eml_details = extract_eml_details(eml_file_path)
    review = review_email_with_gpt4(eml_details)

    print("Email Review by GPT-4:")
    print(f"From: {eml_details['from']}")
    print(f"To: {eml_details['to']}")
    print(f"Subject: {eml_details['subject']}")
    print("Analysis:")
    print(review)

if __name__ == "__main__":
    eml_file_path = "mail.eml"  # Replace with your .eml file path
    main(eml_file_path)