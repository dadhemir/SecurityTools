import requests
import json
import socket
import shodan
import re
import openai
import boto3
from botocore.exceptions import ClientError
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, PageBreak
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib.colors import HexColor
from datetime import datetime
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# === API Keys ===
HIBP_API_KEY = os.getenv("HIBP_API_KEY")
EMAILREP_API_KEY = os.getenv("EMAILREP_API_KEY")
SHODAN_API_KEY = os.getenv("SHODAN_API_KEY")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")

# === AWS SES Configuration ===
AWS_REGION = os.getenv("AWS_REGION", "us-west-2")
SENDER_EMAIL = os.getenv("SENDER_EMAIL", "security@platzi.com")

# === Environment Validation ===
def validate_environment():
    """Validate that all required environment variables are set"""
    missing_vars = []
    
    if not HIBP_API_KEY:
        missing_vars.append("HIBP_API_KEY")
    if not EMAILREP_API_KEY:
        missing_vars.append("EMAILREP_API_KEY")
    if not SHODAN_API_KEY:
        missing_vars.append("SHODAN_API_KEY")
    if not OPENAI_API_KEY:
        missing_vars.append("OPENAI_API_KEY")
    
    if missing_vars:
        print("❌ Missing required environment variables:")
        for var in missing_vars:
            print(f"   - {var}")
        print("\nPlease check your .env file and ensure all variables are set.")
        return False
    
    print("✅ All environment variables loaded successfully!")
    return True



# === Helper Functions ===
def is_email(value):
    return re.match(r"[^@]+@[^@]+\.[^@]+", value)

def query_emailrep(email):
    url = f"https://emailrep.io/{email}"
    headers = {"Accept": "application/json"}
    if EMAILREP_API_KEY:
        headers["Key"] = EMAILREP_API_KEY

    try:
        response = requests.get(url, headers=headers)
        return response.json() if response.status_code == 200 else {"error": f"EmailRep Error {response.status_code}"}
    except Exception as e:
        return {"error": str(e)}

def query_hibp(email):
    url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}?truncateResponse=false"
    headers = {
        "hibp-api-key": HIBP_API_KEY,
        "user-agent": "EmailOSINTScript"
    }

    try:
        response = requests.get(url, headers=headers, params={"truncateResponse": False})
        if response.status_code == 200:
            return response.json()
        elif response.status_code == 404:
            return {"status": "No breaches found"}
        else:
            return {"error": f"HIBP Error {response.status_code}"}
    except Exception as e:
        return {"error": str(e)}

def resolve_domain(domain):
    try:
        return socket.gethostbyname(domain)
    except Exception as e:
        return None

def shodan_lookup(ip):
    api = shodan.Shodan(SHODAN_API_KEY)
    try:
        host = api.host(ip)
        # Limit data to prevent token overflow
        data_summary = []
        if host.get("data"):
            for service in host.get("data")[:3]:  # Only top 3 services
                data_summary.append({
                    "port": service.get("port"),
                    "product": service.get("product"),
                    "version": service.get("version"),
                    "transport": service.get("transport")
                })
        
        return {
            "IP": host.get("ip_str"),
            "Organization": host.get("org"),
            "Operating System": host.get("os"),
            "Ports": host.get("ports", [])[:10],  # Limit to 10 ports
            "Hostnames": host.get("hostnames", [])[:5],  # Limit to 5 hostnames
            "Services": data_summary
        }
    except shodan.APIError as e:
        return {"error": str(e)}

def analyze_with_openai(prompt_text):
    try:
        from openai import OpenAI
        client = OpenAI(api_key=OPENAI_API_KEY)
        response = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {"role": "system", "content": "You are a cybersecurity analyst providing actionable OSINT assessments and security recommendations."},
                {"role": "user", "content": prompt_text}
            ],
            temperature=0.5,
            max_tokens=700
        )
        return response.choices[0].message.content
    except Exception as e:
        return f"Error analyzing with OpenAI: {str(e)}"

def generate_pdf_report(target, emailrep_data, hibp_data, shodan_data, ai_recommendations, report_type):
    """Generate a PDF report with the OSINT analysis results"""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"osint_report_{target.replace('@', '_').replace('.', '_')}_{timestamp}.pdf"
    
    doc = SimpleDocTemplate(filename, pagesize=letter)
    styles = getSampleStyleSheet()
    story = []
    
    # Custom styles
    title_style = ParagraphStyle(
        'CustomTitle',
        parent=styles['Heading1'],
        fontSize=18,
        spaceAfter=30,
        textColor=HexColor('#2E86AB'),
        alignment=1  # Center alignment
    )
    
    header_style = ParagraphStyle(
        'Header',
        parent=styles['Heading2'],
        fontSize=14,
        spaceAfter=20,
        textColor=HexColor('#A23B72'),
        alignment=1
    )
    
    section_style = ParagraphStyle(
        'Section',
        parent=styles['Heading3'],
        fontSize=12,
        spaceAfter=10,
        textColor=HexColor('#F18F01')
    )
    
    # Header
    story.append(Paragraph("Gracias por participar de Platzi CONF 2025!", title_style))
    story.append(Paragraph("Esto es un ejemplo de cómo puedes utilizar AI en ciberseguridad.", header_style))
    story.append(Spacer(1, 20))
    
    # Report info
    story.append(Paragraph(f"<b>OSINT Analysis Report</b>", section_style))
    story.append(Paragraph(f"Target: {target}", styles['Normal']))
    story.append(Paragraph(f"Report Type: {report_type}", styles['Normal']))
    story.append(Paragraph(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", styles['Normal']))
    story.append(Spacer(1, 20))
    
    # EmailRep Analysis
    if report_type == "Email":
        story.append(Paragraph("<b>EmailRep.io Analysis</b>", section_style))
        if "error" not in emailrep_data:
            story.append(Paragraph(f"Email: {target}", styles['Normal']))
            story.append(Paragraph(f"Valid: {emailrep_data.get('valid', 'Unknown')}", styles['Normal']))
            story.append(Paragraph(f"Disposable: {emailrep_data.get('disposable', 'Unknown')}", styles['Normal']))
            story.append(Paragraph(f"Reputation: {emailrep_data.get('reputation', 'Unknown')}", styles['Normal']))
            story.append(Paragraph(f"Suspicious: {emailrep_data.get('suspicious', 'Unknown')}", styles['Normal']))
            story.append(Paragraph(f"Domain: {emailrep_data.get('domain', 'Unknown')}", styles['Normal']))
            if emailrep_data.get('details'):
                details = emailrep_data['details']
                story.append(Paragraph(f"Domain Age: {details.get('domain_age_days', 'Unknown')} days", styles['Normal']))
                story.append(Paragraph(f"Domain Type: {details.get('domain_type', 'Unknown')}", styles['Normal']))
        else:
            story.append(Paragraph(f"Error: {emailrep_data.get('error', 'Unknown error')}", styles['Normal']))
        story.append(Spacer(1, 15))
        
        # HIBP Analysis
        story.append(Paragraph("<b>Have I Been Pwned Analysis</b>", section_style))
        if "error" not in hibp_data and "status" not in hibp_data:
            story.append(Paragraph(f"Email: {target}", styles['Normal']))
            story.append(Paragraph(f"Breaches Found: {len(hibp_data)}", styles['Normal']))
            for i, breach in enumerate(hibp_data[:5], 1):
                story.append(Paragraph(f"{i}. {breach.get('Name', 'Unknown')} ({breach.get('BreachDate', 'Unknown date')})", styles['Normal']))
                story.append(Paragraph(f"   Categories: {', '.join(breach.get('DataClasses', []))}", styles['Normal']))
            if len(hibp_data) > 5:
                story.append(Paragraph(f"   ... and {len(hibp_data) - 5} more breaches", styles['Normal']))
        elif hibp_data.get("status") == "No breaches found":
            story.append(Paragraph(f"Good news! No breaches found for {target}", styles['Normal']))
        else:
            story.append(Paragraph(f"Error: {hibp_data.get('error', 'Unknown error')}", styles['Normal']))
        story.append(Spacer(1, 15))
    
    # Shodan Analysis
    elif report_type == "Domain":
        story.append(Paragraph("<b>Shodan.io Analysis</b>", section_style))
        if "error" not in shodan_data:
            story.append(Paragraph(f"Target: {target}", styles['Normal']))
            story.append(Paragraph(f"IP Address: {shodan_data.get('IP', 'Unknown')}", styles['Normal']))
            story.append(Paragraph(f"Organization: {shodan_data.get('Organization', 'Unknown')}", styles['Normal']))
            story.append(Paragraph(f"OS: {shodan_data.get('Operating System', 'Unknown')}", styles['Normal']))
            
            ports = shodan_data.get('Ports', [])
            if ports:
                story.append(Paragraph(f"Open Ports ({len(ports)}): {', '.join(map(str, ports))}", styles['Normal']))
            
            hostnames = shodan_data.get('Hostnames', [])
            if hostnames:
                story.append(Paragraph(f"Hostnames: {', '.join(hostnames)}", styles['Normal']))
            
            services = shodan_data.get('Services', [])
            if services:
                story.append(Paragraph("Services Found:", styles['Normal']))
                for i, service in enumerate(services, 1):
                    story.append(Paragraph(f"{i}. Port {service.get('port', 'Unknown')}: {service.get('product', 'Unknown')} {service.get('version', '')}", styles['Normal']))
        else:
            story.append(Paragraph(f"Error: {shodan_data.get('error', 'Unknown error')}", styles['Normal']))
        story.append(Spacer(1, 15))
    
    # AI Recommendations
    story.append(Paragraph("<b>AI Security Recommendations</b>", section_style))
    
    # Format AI recommendations for PDF with better structure
    recommendations_lines = ai_recommendations.split('\n')
    for line in recommendations_lines:
        line = line.strip()
        if line:
            if line.startswith('🔸'):
                # Section headers
                clean_line = line.replace('🔸 ', '').replace('🔸', '')
                story.append(Paragraph(f"<b>{clean_line}</b>", styles['Heading4']))
            elif line.startswith('📋'):
                # Subsection headers
                clean_line = line.replace('📋 ', '').replace('📋', '')
                story.append(Paragraph(f"<b>{clean_line}</b>", styles['Normal']))
            elif line.startswith(('•', '-', '*', '1.', '2.', '3.', '4.', '5.')):
                # Bullet points and numbered lists
                story.append(Paragraph(f"  {line}", styles['Normal']))
            else:
                # Regular text
                story.append(Paragraph(line, styles['Normal']))
    
    story.append(Spacer(1, 20))
    
    # Build PDF
    doc.build(story)
    return filename

def configure_aws_ses():
    """Show AWS SES configuration instructions"""
    print("\n🔧 AWS SES Configuration")
    print("=" * 50)
    print("To use email functionality, you need to:")
    print("1. Install boto3: pip install boto3")
    print("2. Configure AWS credentials (AWS CLI or environment variables)")
    print("3. Set up AWS SES in your region")
    print("4. Verify your sender email address in SES console")
    print("5. Update the configuration variables in the script:")
    print(f"   - AWS_REGION: {AWS_REGION}")
    print(f"   - SENDER_EMAIL: {SENDER_EMAIL}")
    print("\nCurrent settings:")
    print(f"   AWS Region: {AWS_REGION}")
    print(f"   Sender Email: {SENDER_EMAIL}")
    print("\nTo update these settings, edit the configuration variables in the script.")

def send_email_with_attachment(pdf_filename, target, report_type, recipient_email):
    """Send email with PDF attachment using AWS SES"""
    try:
        # Create SES client
        ses_client = boto3.client('ses', region_name=AWS_REGION)
        
        # Email content
        subject = f"OSINT Security Report - {target} ({report_type})"
        
        html_body = f"""
        <html>
        <head></head>
        <body>
            <h2>🔍 OSINT Security Analysis Report</h2>
            <p><strong>Target:</strong> {target}</p>
            <p><strong>Report Type:</strong> {report_type}</p>
            <p><strong>Generated:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            <br>
            <p>This report contains the results of our OSINT analysis including:</p>
            <ul>
                <li>EmailRep.io analysis (for email targets)</li>
                <li>Have I Been Pwned breach data (for email targets)</li>
                <li>Shodan.io infrastructure analysis (for domain targets)</li>
                <li>AI-powered security recommendations</li>
            </ul>
            <br>
            <p><strong>⚠️ Important:</strong> This report is for educational and security assessment purposes only.</p>
            <br>
            <p>Best regards,<br>Platzi Team</p>
        </body>
        </html>
        """
        
        text_body = f"""
        OSINT Security Analysis Report
        
        Target: {target}
        Report Type: {report_type}
        Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
        
        This report contains the results of our OSINT analysis including:
        - EmailRep.io analysis (for email targets)
        - Have I Been Pwned breach data (for email targets)
        - Shodan.io infrastructure analysis (for domain targets)
        - AI-powered security recommendations
        
        Important: This report is for educational and security assessment purposes only.
        
        Best regards,
        Platzi Team
        """
        
        # Read PDF file
        with open(pdf_filename, 'rb') as pdf_file:
            pdf_content = pdf_file.read()
        
        # Create MIME message
        import email
        from email.mime.multipart import MIMEMultipart
        from email.mime.text import MIMEText
        from email.mime.application import MIMEApplication
        
        # Create message
        msg = MIMEMultipart('mixed')
        msg['Subject'] = subject
        msg['From'] = SENDER_EMAIL
        msg['To'] = recipient_email
        
        # Create the HTML part
        html_part = MIMEText(html_body, 'html', 'utf-8')
        html_part.add_header('Content-Disposition', 'inline')
        
        # Create the text part
        text_part = MIMEText(text_body, 'plain', 'utf-8')
        text_part.add_header('Content-Disposition', 'inline')
        
        # Create the multipart alternative
        msg_alternative = MIMEMultipart('alternative')
        msg_alternative.attach(text_part)
        msg_alternative.attach(html_part)
        
        # Attach the multipart alternative to the main message
        msg.attach(msg_alternative)
        
        # Attach PDF
        pdf_attachment = MIMEApplication(pdf_content, _subtype='pdf')
        pdf_attachment.add_header('Content-Disposition', 'attachment', filename=pdf_filename)
        msg.attach(pdf_attachment)
        
        # Convert to string
        raw_message = msg.as_string()
        
        # Send email
        response = ses_client.send_raw_email(
            Source=SENDER_EMAIL,
            Destinations=[recipient_email],
            RawMessage={'Data': raw_message}
        )
        
        print(f"📧 Email sent successfully! Message ID: {response['MessageId']}")
        return True
        
    except ClientError as e:
        print(f"❌ Error sending email: {e.response['Error']['Message']}")
        return False
    except Exception as e:
        print(f"❌ Unexpected error sending email: {str(e)}")
        return False

# === Main Logic ===
def run_osint():
    target = input("🔎 Enter an email address or domain: ").strip()

    if is_email(target):
        print(f"\n📧 Running Email OSINT on: {target}")
        emailrep_data = query_emailrep(target)
        hibp_data = query_hibp(target)

        print("\n🔍 EmailRep.io Analysis:")
        print("=" * 50)
        if "error" not in emailrep_data:
            print(f"📧 Email: {target}")
            print(f"✅ Valid: {emailrep_data.get('valid', 'Unknown')}")
            print(f"🛡️  Disposable: {emailrep_data.get('disposable', 'Unknown')}")
            print(f"📊 Reputation: {emailrep_data.get('reputation', 'Unknown')}")
            print(f"🎭 Suspicious: {emailrep_data.get('suspicious', 'Unknown')}")
            print(f"📱 Domain: {emailrep_data.get('domain', 'Unknown')}")
            if emailrep_data.get('details'):
                details = emailrep_data['details']
                print(f"📋 Domain Age: {details.get('domain_age_days', 'Unknown')} days")
                print(f"🌐 Domain Type: {details.get('domain_type', 'Unknown')}")
        else:
            print(f"❌ Error: {emailrep_data.get('error', 'Unknown error')}")
        
        print("\n🔍 Have I Been Pwned Analysis:")
        print("=" * 50)
        if "error" not in hibp_data and "status" not in hibp_data:
            print(f"📧 Email: {target}")
            print(f"🚨 Breaches Found: {len(hibp_data)}")
            for i, breach in enumerate(hibp_data[:5], 1):  # Show top 5 breaches
                print(f"  {i}. {breach.get('Name', 'Unknown')} ({breach.get('BreachDate', 'Unknown date')})")
                print(f"     Categories: {', '.join(breach.get('DataClasses', []))}")
            if len(hibp_data) > 5:
                print(f"     ... and {len(hibp_data) - 5} more breaches")
        elif hibp_data.get("status") == "No breaches found":
            print(f"✅ Good news! No breaches found for {target}")
        else:
            print(f"❌ Error: {hibp_data.get('error', 'Unknown error')}")

        ai_prompt = (
            f"Analyze this email OSINT data and provide structured security recommendations. "
            f"Format your response with clear sections:\n\n"
            f"RISK ASSESSMENT:\n"
            f"SECURITY RECOMMENDATIONS:\n"
            f"IMMEDIATE ACTIONS:\n"
            f"LONG-TERM ACTIONS:\n"
            f"CONCLUSION:\n\n"
            f"Data to analyze:\n"
            f"EmailRep: {json.dumps(emailrep_data, separators=(',', ':'))}\n"
            f"HIBP: {json.dumps(hibp_data, separators=(',', ':'))}"
        )
        print("\n🧠 AI Security Recommendations (Email):")
        print("=" * 60)
        ai_recommendations = analyze_with_openai(ai_prompt)
        
        # Format AI recommendations with better structure
        recommendations_lines = ai_recommendations.split('\n')
        formatted_recommendations = []
        
        for line in recommendations_lines:
            line = line.strip()
            if line:
                if line.startswith(('•', '-', '*', '1.', '2.', '3.', '4.', '5.')):
                    print(f"  {line}")
                    formatted_recommendations.append(f"  {line}")
                elif line.upper() in ['RISK ASSESSMENT:', 'SECURITY RECOMMENDATIONS:', 'IMMEDIATE ACTIONS:', 'LONG-TERM ACTIONS:', 'CONCLUSION:']:
                    print(f"\n🔸 {line.upper()}")
                    formatted_recommendations.append(f"\n🔸 {line.upper()}")
                elif line.endswith(':') and len(line) < 50:
                    print(f"\n📋 {line}")
                    formatted_recommendations.append(f"\n📋 {line}")
                else:
                    print(f"  {line}")
                    formatted_recommendations.append(f"  {line}")
        
        # Store formatted recommendations for PDF
        ai_recommendations = '\n'.join(formatted_recommendations)
        
        # Generate PDF report
        try:
            pdf_filename = generate_pdf_report(target, emailrep_data, hibp_data, {}, ai_recommendations, "Email")
            print(f"\n📄 PDF Report generated: {pdf_filename}")
            
            # Ask if user wants to send email
            send_email = input("\n📧 Do you want to send the report via email? (y/n): ").strip().lower()
            if send_email in ['y', 'yes']:
                recipient = input("📧 Enter recipient email address: ").strip()
                if recipient:
                    if send_email_with_attachment(pdf_filename, target, "Email", recipient):
                        print("✅ Email sent successfully!")
                    else:
                        print("❌ Failed to send email. Check AWS SES configuration.")
                else:
                    print("❌ No recipient email provided.")
            else:
                print("📧 Email sending skipped.")
                
        except Exception as e:
            print(f"\n❌ Error generating PDF: {str(e)}")

    else:
        print(f"\n🌐 Running Domain OSINT on: {target}")
        ip = resolve_domain(target)
        if not ip:
            print("❌ Could not resolve domain to IP.")
            return

        print(f"Resolved IP: {ip}")
        shodan_data = shodan_lookup(ip)

        print("\n🔍 Shodan.io Analysis:")
        print("=" * 50)
        if "error" not in shodan_data:
            print(f"🌐 Target: {target}")
            print(f"📍 IP Address: {shodan_data.get('IP', 'Unknown')}")
            print(f"🏢 Organization: {shodan_data.get('Organization', 'Unknown')}")
            print(f"💻 OS: {shodan_data.get('Operating System', 'Unknown')}")
            
            ports = shodan_data.get('Ports', [])
            if ports:
                print(f"🔌 Open Ports ({len(ports)}): {', '.join(map(str, ports))}")
            
            hostnames = shodan_data.get('Hostnames', [])
            if hostnames:
                print(f"🏷️  Hostnames: {', '.join(hostnames)}")
            
            services = shodan_data.get('Services', [])
            if services:
                print(f"🔧 Services Found:")
                for i, service in enumerate(services, 1):
                    print(f"  {i}. Port {service.get('port', 'Unknown')}: {service.get('product', 'Unknown')} {service.get('version', '')}")
        else:
            print(f"❌ Error: {shodan_data.get('error', 'Unknown error')}")

        ai_prompt = (
            f"Analyze this Shodan scan and provide structured security recommendations. "
            f"Format your response with clear sections:\n\n"
            f"RISK ASSESSMENT:\n"
            f"VULNERABILITIES:\n"
            f"SECURITY RECOMMENDATIONS:\n"
            f"IMMEDIATE ACTIONS:\n"
            f"LONG-TERM ACTIONS:\n"
            f"CONCLUSION:\n\n"
            f"Data to analyze:\n"
            f"Shodan Data: {json.dumps(shodan_data, separators=(',', ':'))}"
        )
        print("\n🧠 AI Security Recommendations (Domain):")
        print("=" * 60)
        ai_recommendations = analyze_with_openai(ai_prompt)
        
        # Format AI recommendations with better structure
        recommendations_lines = ai_recommendations.split('\n')
        formatted_recommendations = []
        
        for line in recommendations_lines:
            line = line.strip()
            if line:
                if line.startswith(('•', '-', '*', '1.', '2.', '3.', '4.', '5.')):
                    print(f"  {line}")
                    formatted_recommendations.append(f"  {line}")
                elif line.upper() in ['RISK ASSESSMENT:', 'SECURITY RECOMMENDATIONS:', 'IMMEDIATE ACTIONS:', 'LONG-TERM ACTIONS:', 'VULNERABILITIES:', 'CONCLUSION:']:
                    print(f"\n🔸 {line.upper()}")
                    formatted_recommendations.append(f"\n🔸 {line.upper()}")
                elif line.endswith(':') and len(line) < 50:
                    print(f"\n📋 {line}")
                    formatted_recommendations.append(f"\n📋 {line}")
                else:
                    print(f"  {line}")
                    formatted_recommendations.append(f"  {line}")
        
        # Store formatted recommendations for PDF
        ai_recommendations = '\n'.join(formatted_recommendations)
        
        # Generate PDF report
        try:
            pdf_filename = generate_pdf_report(target, {}, {}, shodan_data, ai_recommendations, "Domain")
            print(f"\n📄 PDF Report generated: {pdf_filename}")
            
            # Ask if user wants to send email
            send_email = input("\n📧 Do you want to send the report via email? (y/n): ").strip().lower()
            if send_email in ['y', 'yes']:
                recipient = input("📧 Enter recipient email address: ").strip()
                if recipient:
                    if send_email_with_attachment(pdf_filename, target, "Domain", recipient):
                        print("✅ Email sent successfully!")
                    else:
                        print("❌ Failed to send email. Check AWS SES configuration.")
                else:
                    print("❌ No recipient email provided.")
            else:
                print("📧 Email sending skipped.")
                
        except Exception as e:
            print(f"\n❌ Error generating PDF: {str(e)}")


# === Run ===
if __name__ == "__main__":
    print("🔍 OSINT Security Analysis Tool")
    print("=" * 50)
    print("1. Run OSINT Analysis")
    print("2. Exit")
    
    choice = input("\nSelect an option (1-2): ").strip()
    
    if choice == "1":
        if validate_environment():
            run_osint()
        else:
            print("❌ Please fix the environment variables before running the analysis.")
    elif choice == "2":
        print("👋 Goodbye!")
    else:
        print("❌ Invalid option. Please try again.")