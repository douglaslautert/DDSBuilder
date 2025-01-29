import json
import re
from datetime import datetime as dt
from requests.auth import HTTPBasicAuth
import google.generativeai as genai
import os
import time
from openai import OpenAI
from llamaapi import LlamaAPI

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
# categorize vulnerabilite with chat-GPT
def categorize_vulnerability_gpt(description):
    """Categorizes the vulnerability and extracts cause, impact, and vendor using Chat GPT."""
    client = OpenAI(
    api_key = os.environ["CHAT_API_KEY"]
    )

    prompt = f"""
    You are a security expert.
    Categorize the following vulnerability description into a CWE category, identify the vendor, and extract the cause and impact of the vulnerability.
    Provide the CWE ID, a brief explanation, the vendor name, the cause of the vulnerability, and its impact.

    Description:
    ```
    {description}
    ```

    Output:
    ```json
    {{"cwe_category": "CWE-ID", "explanation": "Brief Explanation of the CWE", "vendor": "Vendor Name", "cause": "Cause of the Vulnerability", "impact": "Impact of the Vulnerability"}}
    ```
    """
    time.sleep(1)

    completion = client.chat.completions.create(
    model="gpt-4o-mini",
    store=True,
    messages=[
            {"role": "user", "content": prompt}])

    print(completion.choices[0].message.content);

    text_part = completion.choices[0].message.content

    # Extrair o JSON usando expressão regular
    match = re.search(r'``[`json\n(.*?)\n`](command:_github.copilot.openSymbolFromReferences?%5B%22%22%2C%5B%7B%22uri%22%3A%7B%22scheme%22%3A%22file%22%2C%22authority%22%3A%22%22%2C%22path%22%3A%22%2Fd%3A%2FMESTRADO%2FDDS%2FSCRAP_DDS%2Fscrap_generate_dataset.py%22%2C%22query%22%3A%22%22%2C%22fragment%22%3A%22%22%7D%2C%22pos%22%3A%7B%22line%22%3A2%2C%22character%22%3A7%7D%7D%5D%2C%224136289f-5814-4b75-9d6f-56e9b5bfd10d%22%5D "Go to definition")``', text_part, re.DOTALL)
    if match:
                    json_str = match.group(1)
                    
                    try:
                        result = json.loads(json_str, strict=False)
                        cwe_category = result.get('cwe_category', 'Unknown')
                        explanation = result.get('explanation', 'Could not categorize vulnerability')
                        vendor = result.get('vendor', 'Unknown')
                        cause = result.get('cause', 'Unknown')
                        impact = result.get('impact', 'Unknown')
                        return [(cwe_category, explanation, vendor, cause, impact)]
                    except json.JSONDecodeError:
                        print(f"Error parsing JSON from Chat-GPT response: {json_str}")
                        return [("UNKNOWN", "Error categorizing vulnerability", "Unknown", "Unknown", "Unknown")]
    else:
                    print(f"Could not find JSON in Chat-GPT response: {text_part}")
                    return [("UNKNOWN", "Could not find JSON in Gemini response", "Unknown", "Unknown", "Unknown")]


# categorize vulnerabilite with chat-GPT
def categorize_vulnerability_llama(description):
    """Categorizes the vulnerability and extracts cause, impact, and vendor using Chat GPT."""
    client = OpenAI(
    api_key = os.environ["CHAT_API_KEY"]
    )
    llama = LlamaAPI(os.environ["LLAMA_API_KEY"])
    prompt = f"""
    You are a security expert.
    Categorize the following vulnerability description into a CWE category, identify the vendor, and extract the cause and impact of the vulnerability.
    Provide the CWE ID, a brief explanation, the vendor name, the cause of the vulnerability, and its impact.

    Description:
    ```
    {description}
    ```

    Output:
    ```json
    {{"cwe_category": "CWE-ID", "explanation": "Brief Explanation of the CWE", "vendor": "Vendor Name", "cause": "Cause of the Vulnerability", "impact": "Impact of the Vulnerability"}}
    ```
    """
    time.sleep(1)

    # Define your API request
    api_request_json = {
    "messages": [
        {"role": "user", "content": prompt},
    ],
    "functions": [
        {
            "name": "get_current_weather",
            "description": "Get the current weather in a given location",
            "parameters": {
                "type": "object",
                "properties": {
                    "location": {
                        "type": "string",
                        "description": "The city and state, e.g. San Francisco, CA",
                    },
                    "days": {
                        "type": "number",
                        "description": "for how many days ahead you wants the forecast",
                    },
                    "unit": {"type": "string", "enum": ["celsius", "fahrenheit"]},
                },
            },
            "required": ["location", "days"],
        }
    ],
    "stream": False,
    "function_call": "get_current_weather",
    }

    # Make your request and handle the response
    response = llama.run(api_request_json)
    print(json.dumps(response.json(), indent=2))

    text_part = json.dumps(response.json(), indent=2)

    # Extrair o JSON usando expressão regular
    match = re.search(r'``[`json\n(.*?)\n`](command:_github.copilot.openSymbolFromReferences?%5B%22%22%2C%5B%7B%22uri%22%3A%7B%22scheme%22%3A%22file%22%2C%22authority%22%3A%22%22%2C%22path%22%3A%22%2Fd%3A%2FMESTRADO%2FDDS%2FSCRAP_DDS%2Fscrap_generate_dataset.py%22%2C%22query%22%3A%22%22%2C%22fragment%22%3A%22%22%7D%2C%22pos%22%3A%7B%22line%22%3A2%2C%22character%22%3A7%7D%7D%5D%2C%224136289f-5814-4b75-9d6f-56e9b5bfd10d%22%5D "Go to definition")``', text_part, re.DOTALL)
    if match:
                    json_str = match.group(1)
                    
                    try:
                        result = json.loads(json_str, strict=False)
                        cwe_category = result.get('cwe_category', 'Unknown')
                        explanation = result.get('explanation', 'Could not categorize vulnerability')
                        vendor = result.get('vendor', 'Unknown')
                        cause = result.get('cause', 'Unknown')
                        impact = result.get('impact', 'Unknown')
                        return [(cwe_category, explanation, vendor, cause, impact)]
                    except json.JSONDecodeError:
                        print(f"Error parsing JSON from Chat-GPT response: {json_str}")
                        return [("UNKNOWN", "Error categorizing vulnerability", "Unknown", "Unknown", "Unknown")]
    else:
                    print(f"Could not find JSON in Chat-GPT response: {text_part}")
                    return [("UNKNOWN", "Could not find JSON in Gemini response", "Unknown", "Unknown", "Unknown")]


# categorize vulnerabilite with gemini
def categorize_vulnerability_gemini(description):
    """Categorizes the vulnerability and extracts cause, impact, and vendor using Google Gemini."""
    genai.configure(api_key=os.environ["GOOGLE_API_KEY"])
    model = genai.GenerativeModel('gemini-1.5-pro')

    prompt = f"""
    You are a security expert.
    Categorize the following vulnerability description into a CWE category, identify the vendor, and extract the cause and impact of the vulnerability.
    Provide the CWE ID, a brief explanation, the vendor name, the cause of the vulnerability, and its impact.

    Description:
    ```
    {description}
    ```

    Output:
    ```json
    {{"cwe_category": "CWE-ID", "explanation": "Brief Explanation of the CWE", "vendor": "Vendor Name", "cause": "Cause of the Vulnerability", "impact": "Impact of the Vulnerability"}}
    ```
    """
    time.sleep(1)

    try:
        response = model.generate_content(prompt, safety_settings=safe)
        print(response)

        if response._result.candidates:
            if response._result.candidates[0].content.parts:
                text_part = response._result.candidates[0].content.parts[0].text

                # Extrair o JSON usando expressão regular
                match = re.search(r'``[`json\n(.*?)\n`](command:_github.copilot.openSymbolFromReferences?%5B%22%22%2C%5B%7B%22uri%22%3A%7B%22scheme%22%3A%22file%22%2C%22authority%22%3A%22%22%2C%22path%22%3A%22%2Fd%3A%2FMESTRADO%2FDDS%2FSCRAP_DDS%2Fscrap_generate_dataset.py%22%2C%22query%22%3A%22%22%2C%22fragment%22%3A%22%22%7D%2C%22pos%22%3A%7B%22line%22%3A2%2C%22character%22%3A7%7D%7D%5D%2C%224136289f-5814-4b75-9d6f-56e9b5bfd10d%22%5D "Go to definition")``', text_part, re.DOTALL)
                if match:
                    json_str = match.group(1)
                    
                    try:
                        result = json.loads(json_str, strict=False)
                        cwe_category = result.get('cwe_category', 'Unknown')
                        explanation = result.get('explanation', 'Could not categorize vulnerability')
                        vendor = result.get('vendor', 'Unknown')
                        cause = result.get('cause', 'Unknown')
                        impact = result.get('impact', 'Unknown')
                        return [(cwe_category, explanation, vendor, cause, impact)]
                    except json.JSONDecodeError:
                        print(f"Error parsing JSON from Gemini response: {json_str}")
                        return [("UNKNOWN", "Error categorizing vulnerability", "Unknown", "Unknown", "Unknown")]
                else:
                    print(f"Could not find JSON in Gemini response: {text_part}")
                    return [("UNKNOWN", "Could not find JSON in Gemini response", "Unknown", "Unknown", "Unknown")]

            else:
                print(f"Gemini response has no parts: {response.result}")
                return [("UNKNOWN", "Gemini response has no parts", "Unknown", "Unknown", "Unknown")]
        else:
            print(f"Gemini returned no candidates: {response.result}")
            return [("UNKNOWN", "Gemini returned no candidates", "Unknown", "Unknown", "Unknown")]

    except Exception as e:
        print(f"Error calling Gemini API: {e}")
        return [("UNKNOWN", "Error calling Gemini API", "Unknown", "Unknown", "Unknown")]
