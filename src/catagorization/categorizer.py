import json
import re
from datetime import datetime as dt
import google.generativeai as genai
import os
import time
from openai import OpenAI
from transformers import pipeline

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
        Categorizes the vulnerability and extracts cause, impact, and vendor using Chat GPT.
        """
        client = OpenAI(
            api_key=os.environ["CHATGPT_API_KEY"]
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

        try:
            completion = client.chat.completions.create(
                model="gpt-4o-mini",
                store=True,
                messages=[
                    {"role": "user", "content": prompt}
                ]
            )
            print(completion)

            text_part = completion.choices[0].message.content

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
                    print(f"Error parsing JSON from Chat-GPT response: {json_str}")
                    return [("UNKNOWN", "Error categorizing vulnerability", "Unknown", "Unknown", "Unknown")]
            else:
                print(f"Could not find JSON in Chat-GPT response: {text_part}")
                return [("UNKNOWN", "Could not find JSON in Chat-GPT response", "Unknown", "Unknown", "Unknown")]

        except Exception as e:
            print(f"Error calling Chat-GPT API: {e}")
            return [("UNKNOWN", "Error calling Chat-GPT API", "Unknown", "Unknown", "Unknown")]


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
        Uses the Llama API to categorize a vulnerability based on its description.
        Expects the response to contain a JSON formatted answer with keys: cwe_category, explanation, vendor, cause, impact.
        """
        client = OpenAI(
            api_key=os.environ["LLAMA_API_KEY"],
            base_url="https://api.llama-api.com"
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

        try:
            response = client.chat.completions.create(
                model="llama3.1-70b",
                messages=[
                    {"role": "user", "content": prompt}
                ],
            )
            print(response)
            text_part = response.choices[0].message.content

            # Extract JSON using regex
            match = re.search(r'``[json\s*(\{.*?\})\s*](http://_vscodecontentref_/2)``', text_part, re.DOTALL)
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
                    print(f"Error parsing JSON from Llama response: {json_str}")
                    return [("UNKNOWN", "Error categorizing vulnerability", "Unknown", "Unknown", "Unknown")]
            else:
                print(f"Could not find JSON in Llama response: {text_part}")
                return [("UNKNOWN", "Could not find JSON in Llama response", "Unknown", "Unknown", "Unknown")]

        except Exception as e:
            print(f"Error calling Llama API: {e}")
            return [("UNKNOWN", "Error calling Llama API", "Unknown", "Unknown", "Unknown")]

    def _vote(self, items):
        """
        Simple voting mechanism to choose the most common item.
        """
        return max(set(items), key=items.count)

    def categorize_vulnerability_combined(self, description):
        """
        Combines the results from Gemini, ChatGPT, and Llama to generate the best categorization.
        """
        results = []
        results.append(self.categorize_vulnerability_gemini(description))
        results.append(self.categorize_vulnerability_gpt(description))
        results.append(self.categorize_vulnerability_llama(description))

        # Combine results using a simple voting mechanism
        combined_result = {
            "cwe_category": self._vote([result[0][0] for result in results]),
            "explanation": self._vote([result[0][1] for result in results]),
            "vendor": self._vote([result[0][2] for result in results]),
            "cause": self._vote([result[0][3] for result in results]),
            "impact": self._vote([result[0][4] for result in results])
        }
        return [(combined_result["cwe_category"], combined_result["explanation"], combined_result["vendor"], combined_result["cause"], combined_result["impact"])]

    def categorize_vulnerability_default(self, description):
        """
        Default categorization method that does not use any LLM.
        """
        return [("UNKNOWN", "No categorization available", "Unknown", "Unknown", "Unknown")]