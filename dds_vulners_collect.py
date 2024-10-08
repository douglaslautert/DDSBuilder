import requests
import csv
import json
import re
from datetime import datetime as dt
from requests.auth import HTTPBasicAuth
import google.generativeai as genai
import os
import time


# ***** CONFIGURATION *****
GEMINI_API_KEY = "GEMINI_API_KEY" # Replace with your Gemini API key
VULNERS_API_KEY = "VULNERS_API_KEY" # Replace with your actual Vulners API key
CSV_OUTPUT_FILE = "dds_vulnerabilities_AI.csv" # Change the output file name
# ***** END CONFIGURATION *****
# Safety configuration for Gemini
safe = [
    {
        "category": "HARM_CATEGORY_HARASSMENT",
        "threshold": "BLOCK_NONE",
    },
    {
        "category": "HARM_CATEGORY_HATE_SPEECH",
        "threshold": "BLOCK_NONE",
    },
    {
        "category": "HARM_CATEGORY_SEXUALLY_EXPLICIT",
        "threshold": "BLOCK_NONE",
    },
    {
        "category": "HARM_CATEGORY_DANGEROUS_CONTENT",
        "threshold": "BLOCK_NONE",
    },
]


VENDORS = [
    "TiTAN DDS", "CoreDX", "Core DX", "Zhenrong DDS", "MilDDS", "Mil DDS", "GurumDDS", "InterCOM",
    "Fast DDS", "fastdds", "cyclonedds", "connext", "opendds", "data distribution service vulnerabilities"
]

FIELDS = ["bulletinFamily", "cvss", "description", "id", "lastseen", "modified", "published", "title", "type", "vhref", "viewCount", "href", "enchantments", "bounty", "sourceData", "cvss3", "cvss2", "epss"]

def get_vulners_data(query, fields, skip=0):
    """Searches for vulnerabilities using the Vulners API."""
    base_url = "https://vulners.com/api/v3/search/search"
    data = {
        'query': query,
        'fields': fields,
        'skip': skip,
        'apiKey': VULNERS_API_KEY 
    }
    response = requests.post(base_url, data=json.dumps(data))
    response.raise_for_status()
    return response.json()


def extract_vulners_data(vulnerability):
    """Extracts relevant information from a Vulners vulnerability entry, handling encoding."""
    description = vulnerability.get('_source', {}).get('description')
    description = description.encode('utf-8', errors='replace').decode('utf-8')
    max_length = 500
    if len(description) > max_length:
        key_phrases = ["allows", "to cause", "via", "in", "component"]
        extracted_parts = []
        for sentence in description.split(". "):
            for phrase in key_phrases:
                if phrase in sentence:
                    extracted_parts.append(sentence)
                    break
        truncated_description = ". ".join(extracted_parts[:2]) + "..."
    else:
        truncated_description = description

    description_without_punct = re.sub(r'[^\w\s]', '', truncated_description).lower()

    vendor = 'UNKNOWN'
    for v in VENDORS:
        v_without_punct = re.sub(r'[^\w\s]', '', v).lower()
        if v_without_punct in description_without_punct:
            vendor = v
            break

    cvss_data = vulnerability.get('_source', {})
    return {
        'id': vulnerability.get('_source', {}).get('id'),
        'title': vulnerability.get('_source', {}).get('title'),
        'description': truncated_description,
        'vendor': vendor,
        'published': vulnerability.get('_source', {}).get('published'),
        'cvss': vulnerability.get('_source', {}).get('cvss', {}).get('score'), # vulners cvss is on score
        'severity': vulnerability.get('_source', {}).get('cvss', {}).get('severity'), # vulners severity is on severity
        'source': 'Vulners'
    }

def categorize_vulnerability(description):
    """Categorizes the vulnerability using Google Gemini."""
    genai.configure(api_key=os.environ["GOOGLE_API_KEY"])
    model = genai.GenerativeModel('gemini-1.5-pro')


    prompt = f"""
    You are a security expert. \
    Categorize the following vulnerability description into a CWE category. \
    Provide the CWE ID and a brief explanation.

    Description:
    ```
    {description}
    ```

    Output:
    ```json
    {{"cwe_category": "CWE-ID", "explanation": "Brief Explanation of the CWE"}}
    ```
    """
    time.sleep(1)
    
    try:
        response = model.generate_content(prompt, safety_settings=safe)
        print(response)
        if response._result.candidates:

            if response._result.candidates[0].content.parts:
                text_part = response._result.candidates[0].content.parts[0].text
                json_str = response._result.candidates[0].content.parts[0].text.strip().replace("```json\n", "").replace("\n```", "")
                result = json.loads(json_str, strict=False)
                return result['cwe_category'], result['explanation']
            else:
                print(f"Gemini response has no parts: {response._result}")
                return "UNKNOWN", "Gemini response has no parts"
        else:
            print(f"Gemini returned no candidates: {response._result}")
            return "UNKNOWN", "Gemini returned no candidates"

    except json.JSONDecodeError as e:
        print(f"Error parsing JSON from Gemini response: {json_str}, Error: {e}")
        return "UNKNOWN", "Error categorizing vulnerability"
    except Exception as e:
        print(f"Error calling Gemini API: {e}")
        return "UNKNOWN", "Error calling Gemini API"

def write_to_csv(data, filename):
    """Writes the extracted vulnerability data to a CSV file, 
    avoiding duplicates and using Gemini for categorization.
    """
    fieldnames = ['id', 'title', 'description', 'vendor', 'published', 
                  'cvss', 'cvss_score', 'severity', 'attack_vector', 
                  'cwe_category', 'cwe_explanation', 'source']
    existing_vulnerabilities = set()

    try:
        with open(filename, 'r', encoding="utf-8") as csvfile:
            reader = csv.DictReader(csvfile)
            for row in reader:
                existing_vulnerabilities.add(row['id'])
    except FileNotFoundError:
        pass

    with open(filename, 'a', newline='', encoding="utf-8") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        if len(existing_vulnerabilities) == 0:
            writer.writeheader()
        for item in data:
            if item['id'] not in existing_vulnerabilities:
                # Use Gemini to categorize the vulnerability
                item['cwe_category'], item['cwe_explanation'] = categorize_vulnerability(item['description'])
                writer.writerow(item)
                existing_vulnerabilities.add(item['id'])

def main():
    """Orchestrates the vulnerability search and data extraction process."""
    all_vulnerabilities = []
    
    # --- Vulners ---
    for vendor in VENDORS:
        skip = 0 
        while True:
            data = get_vulners_data(f'"{vendor}"', FIELDS, skip) # formatted query for each vendor
            new_vulnerabilities = [extract_vulners_data(cve) for cve in data['data']['search']]
            all_vulnerabilities.extend(new_vulnerabilities)
            total = data['data']['total']
            skip += len(data['data']['search'])  # Use actual returned results for pagination
            if skip >= total:
                break

    # Write to CSV, avoiding duplicates and using Gemini
    write_to_csv(all_vulnerabilities, CSV_OUTPUT_FILE)
    print(f"Vulnerability data saved to {CSV_OUTPUT_FILE}")

if __name__ == "__main__":
    main()