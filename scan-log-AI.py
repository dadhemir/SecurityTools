import openai
import pandas as pd

# Set up OpenAI API key (make sure to replace 'your-api-key' with your actual API key)
openai.api_key = '### your Key ###'

# Load the firewall log file. View input folder
file_path = 'log-fw.xlsx'
df = pd.read_excel(file_path)

# Preprocess the log data (adjust this based on the actual structure of your log file)
# Example: Select relevant columns and convert them to a string format for analysis
log_data = df[['hour', 'string', 'iface', 'protocol', 'source', 'source-port', 'mac', 'target', 'target-port']].astype(str)
log_text = log_data.to_string(index=False)

# Define a prompt for GPT-4 to analyze the log data
prompt = f"""
Analyze the following firewall log data and identify any possible attacks or suspicious activities.
Provide a summary of your findings:

{log_text}
"""

# Make the API call to GPT-4
response = openai.ChatCompletion.create(
    model="gpt-4o-2024-05-13",
    messages=[
        {"role": "system", "content": "You are a cybersecurity expert."},
        {"role": "user", "content": prompt}
    ]
)

# Extract the generated text
summary = response['choices'][0]['message']['content']

# Save the summary to a .txt file
output_file = 'firewall_analysis_summary.txt'
with open(output_file, 'w') as file:
    file.write(summary)

print(f"Summary of possible attacks or suspicious activities saved to {output_file}.")