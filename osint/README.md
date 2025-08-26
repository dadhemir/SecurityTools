# OSINT Security Analysis Tool

A comprehensive OSINT (Open Source Intelligence) tool that analyzes email addresses and domains using multiple security APIs and AI-powered recommendations.

## Features

- **Email Analysis**: EmailRep.io and Have I Been Pwned integration
- **Domain Analysis**: Shodan.io infrastructure scanning
- **AI Recommendations**: OpenAI-powered security insights
- **PDF Reports**: Professional report generation
- **Email Delivery**: AWS SES integration for report delivery
- **Environment Security**: API keys stored in .env file

## Setup

### 1. Install Dependencies

```bash
pip install -r requirements.txt
```

### 2. Configure Environment Variables

Create a `.env` file in the project directory with your API keys:

```env
# === API Keys ===
HIBP_API_KEY=your_hibp_api_key_here
EMAILREP_API_KEY=your_emailrep_api_key_here
SHODAN_API_KEY=your_shodan_api_key_here
OPENAI_API_KEY=your_openai_api_key_here

# === AWS SES Configuration ===
AWS_REGION=us-west-2
SENDER_EMAIL=your_verified_sender@yourdomain.com
```

### 3. Get API Keys

- **Have I Been Pwned**: https://haveibeenpwned.com/API/Key
- **EmailRep.io**: https://emailrep.io/
- **Shodan**: https://account.shodan.io/register
- **OpenAI**: https://platform.openai.com/api-keys

### 4. AWS SES Setup (Optional)

For email functionality:
1. Set up AWS SES in your region
2. Verify your sender email address
3. Configure AWS credentials
4. Update AWS_REGION and SENDER_EMAIL in .env

## Usage

```bash
python team-cybersec-osint.py
```

### Menu Options

1. **Run OSINT Analysis**: Analyze email or domain
2. **Configure AWS SES Email**: View email setup instructions
3. **Validate Environment Variables**: Check if all API keys are loaded
4. **Exit**: Close the application

### Analysis Types

- **Email Analysis**: Checks email validity, reputation, and breach history
- **Domain Analysis**: Scans infrastructure for vulnerabilities and open ports

## Output

- **Console Output**: Real-time analysis results with formatted recommendations
- **PDF Reports**: Professional reports with Platzi branding
- **Email Delivery**: Optional email delivery with PDF attachment

## Security Notes

- API keys are stored in `.env` file (not in code)
- `.env` file is excluded from version control
- All analysis is for educational purposes only
- Reports include security disclaimers

## File Structure

```
SecurityTools/osint/
├── team-cybersec-osint.py  # Main application
├── .env                     # Environment variables (create this)
├── .gitignore              # Git ignore rules
├── requirements.txt         # Python dependencies
└── README.md               # This file
```

## Dependencies

- requests: HTTP requests
- shodan: Shodan API integration
- openai: OpenAI API integration
- boto3: AWS SES integration
- reportlab: PDF generation
- python-dotenv: Environment variable loading 