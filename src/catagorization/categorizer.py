import json
import re
from datetime import datetime as dt
import google.generativeai as genai
import os
import time
from openai import OpenAI

# Safety configuration for Gemini
safe = [
    {"category": "HARM_CATEGORY_HARASSMENT", "threshold": "BLOCK_NONE"},
    {"category": "HARM_CATEGORY_HATE_SPEECH", "threshold": "BLOCK_NONE"},
    {"category": "HARM_CATEGORY_SEXUALLY_EXPLICIT", "threshold": "BLOCK_NONE"},
    {"category": "HARM_CATEGORY_DANGEROUS_CONTENT", "threshold": "BLOCK_NONE"},
]

def _extract_category(text_part):
    # Use regex to extract JSON; simplified regex used here for brevity.
    match = re.search(r'```json\s*(\{.*?\})\s*```', text_part, re.DOTALL)
    if match:
        json_str = match.group(1)
        try:
            result = json.loads(json_str, strict=False)
            return {
                "cwe_category": result.get('cwe_category', 'Unknown'),
                "explanation": result.get('explanation', 'Could not categorize vulnerability'),
                "vendor": result.get('vendor', 'Unknown'),
                "cause": result.get('cause', 'Unknown'),
                "impact": result.get('impact', 'Unknown')
            }
        except json.JSONDecodeError:
            print(f"Error parsing JSON: {json_str}")
    print(f"Could not extract categorization from: {text_part}")
    return {"cwe_category": "UNKNOWN", "explanation": "", "vendor": "Unknown", "cause": "", "impact": ""}

class Categorizer:
    def __init__(self):
        # Additional initialization if necessary
        pass

    def categorize_vulnerability_gpt(self, description):
        """
        Uses OpenAI's GPT engine to categorize a vulnerability based on its description.
        Expects the response to contain a JSON formatted answer with keys: cwe_category, explanation, vendor, cause, impact.
        """
        # Ensure the API key is set (e.g., in environment variable CHATGPT_API_KEY)
        openai.api_key = os.environ.get("CHATGPT_API_KEY", "")
        prompt = (
            f"Please analyze the following vulnerability description and provide categorization in JSON format.\n"
            f"JSON must include the following keys: cwe_category, explanation, vendor, cause, impact.\n\n"
            f"Description: {description}\n\n"
            "Respond with markdown formatted JSON (e.g., ```json { ... } ```)."
        )
        try:
            response = openai.Completion.create(
                engine="text-davinci-003",
                prompt=prompt,
                max_tokens=150,
                temperature=0.5,
            )
            output = response.choices[0].text.strip()
            categorization = _extract_category(output)
            return [(categorization["cwe_category"], categorization["explanation"], categorization["vendor"],
                     categorization["cause"], categorization["impact"])]
        except Exception as e:
            print(f"Error during GPT categorization: {e}")
            return None

    def categorize_vulnerability_gemini(self, description):
        """
        Uses Google Generative AI (Gemini) to categorize a vulnerability based on its description.
        Expects the response to contain a JSON formatted answer with keys: cwe_category, explanation, vendor, cause, impact.
        """
        genai_api_key = os.environ.get("GEMINI_API_KEY", "")
        if not genai_api_key:
            print("Gemini API key not found in environment.")
            return None
        genai.configure(api_key=genai_api_key)
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

            if response.candidates:
                if response.candidates[0].content.parts:
                    text_part = response.candidates[0].content.parts[0].text

                    # Extract JSON using regex
                    match = re.search(r'``[json\s*(\{.*?\})\s*](http://_vscodecontentref_/1)``', text_part, re.DOTALL)
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
                    print(f"Gemini response has no parts: {response}")
                    return [("UNKNOWN", "Gemini response has no parts", "Unknown", "Unknown", "Unknown")]
            else:
                print(f"Gemini returned no candidates: {response}")
                return [("UNKNOWN", "Gemini returned no candidates", "Unknown", "Unknown", "Unknown")]

        except Exception as e:
            print(f"Error calling Gemini API: {e}")
            return [("UNKNOWN", "Error calling Gemini API", "Unknown", "Unknown", "Unknown")]


    def categorize_vulnerability_llama(self, description):
        """
        Dummy implementation for Llama categorization.
        Replace this with an actual integration if available.
        """
        # In a real implementation, an API call or local inference for Llama would be performed here.
        # For demonstration, we return a static categorization.
        return [("CWE-20", "Explanation Llama", "VendorName", "Cause details", "Impact details")]
