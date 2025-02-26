import json
import re
from datetime import datetime as dt
import google.generativeai as genai
import os
import asyncio
from openai import OpenAI, AsyncOpenAI
from transformers import AutoTokenizer, AutoModelForCausalLM, pipeline
import ast
# Safety configuration for Gemini
safe = [
    {"category": "HARM_CATEGORY_HARASSMENT", "threshold": "BLOCK_NONE"},
    {"category": "HARM_CATEGORY_HATE_SPEECH", "threshold": "BLOCK_NONE"},
    {"category": "HARM_CATEGORY_SEXUALLY_EXPLICIT", "threshold": "BLOCK_NONE"},
    {"category": "HARM_CATEGORY_DANGEROUS_CONTENT", "threshold": "BLOCK_NONE"},
]

def _extract_category(text_part):
    """Extract JSON from AI response text."""
    # Remove any non-JSON text after the JSON block
    text_part = text_part.split('\n\nExplanation:')[0].strip()
    
    # Try to extract JSON with or without backticks
    patterns = [
        r'```json\s*(\{[\s\S]*?\})\s*```',  # JSON with backticks
        r'\{[\s\S]*?\}'                      # Raw JSON
    ]
    
    for pattern in patterns:
        matches = re.finditer(pattern, text_part, re.DOTALL)
        for match in matches:
            try:
                json_str = match.group(1) if '```' in pattern else match.group(0)
                json_str = json_str.strip()
                result = json.loads(json_str)
                
                # Return structured result if all required fields are present
                if all(k in result for k in ["cwe_category", "explanation", "vendor", "cause", "impact"]):
                    return {
                        "cwe_category": result["cwe_category"],
                        "explanation": result["explanation"],
                        "vendor": result["vendor"],
                        "cause": result["cause"],
                        "impact": result["impact"]
                    }
            except json.JSONDecodeError:
                continue
    
    return {
        "cwe_category": "UNKNOWN",
        "explanation": "",
        "vendor": "Unknown",
        "cause": "",
        "impact": ""
    }

class Categorizer:
    def __init__(self):
        pass

    async def categorize_vulnerability_gpt(self, description):
        client = AsyncOpenAI(api_key=os.environ["CHATGPT_API_KEY"])
        prompt = f"""
        You are a security expert.
        Categorize the following vulnerability description into a CWE category, identify the vendor, and extract the cause and impact of the vulnerability.
        Provide the CWE ID (only the CWE ID of the vulnerability), a brief explanation, the vendor name, the cause of the vulnerability, and its impact.

        Description:
        ```
        {description}
        ```
        Rules for returning the vendor:
        - Return only the official/primary vendor name
        - For open source projects, return the organization maintaining it
        - If multiple vendors are mentioned, return the one responsible for the vulnerable component
        - Normalize variations of the same vendor name
        - If no clear vendor is found, return "Unknown"
        - Use official vendor names where possible and keep the same name for vulnerabilities of the same vendor

        Output:
        ```json
        {{"cwe_category": "CWE-ID", "explanation": "Brief Explanation of the CWE", "vendor": "Vendor Name", "cause": "Cause of the Vulnerability", "impact": "Impact of the Vulnerability"}}
        ```
        """
        try:
            completion = await client.chat.completions.create(
                model="gpt-4o-mini",
                messages=[{"role": "user", "content": prompt}]
            )
            result = _extract_category(completion.choices[0].message.content)
            return [result]
        except Exception as e:
            print(f"Error calling ChatGPT API: {e}")
            return [{"cwe_category": "UNKNOWN", "explanation": str(e), "vendor": "Unknown", "cause": "", "impact": ""}]

    async def categorize_vulnerability_gemini(self, description):
        genai_api_key = os.environ.get("GEMINI_API_KEY", "")
        if not genai_api_key:
            print("Gemini API key not found in environment.")
            return [{ "cwe_category": "UNKNOWN", "explanation": "Gemini API key missing", "vendor": "Unknown", "cause": "Unknown", "impact": "Unknown"}]
        genai.configure(api_key=genai_api_key)
        model = genai.GenerativeModel('gemini-1.5-flash-latest')
        prompt = f"""
        You are a security expert.
        Categorize the following vulnerability description into a CWE category, identify the vendor, and extract the cause and impact of the vulnerability.
        Provide the CWE ID (only the CWE ID of the vulnerability), a brief explanation, the vendor name, the cause of the vulnerability, and its impact.

        Description:
        ```
        {description}
        ```
        Rules for returning the vendor:
        - Return only the official/primary vendor name
        - For open source projects, return the organization maintaining it
        - If multiple vendors are mentioned, return the one responsible for the vulnerable component
        - Normalize variations of the same vendor name
        - If no clear vendor is found, return "Unknown"
        - Use official vendor names where possible and keep the same name for vulnerabilities of the same vendor

        Output:
        ```json
        {{"cwe_category": "CWE-ID", "explanation": "Brief Explanation of the CWE", "vendor": "Vendor Name", "cause": "Cause of the Vulnerability", "impact": "Impact of the Vulnerability"}}
        ```
        """
        try:
            response = await model.generate_content_async(prompt, safety_settings=safe)
            if response.candidates:
                result = _extract_category(response.candidates[0].content.parts[0].text)
                return [result]
        except Exception as e:
            print(f"Error calling Gemini API: {e}")
        return [{"cwe_category": "UNKNOWN", "explanation": "API error", "vendor": "Unknown", "cause": "", "impact": ""}]

    async def categorize_vulnerability_llama(self, description):
        client = AsyncOpenAI(api_key=os.environ["LLAMA_API_KEY"], base_url="https://api.llama-api.com")
        prompt = f"""
        You are a security expert.
        Categorize the following vulnerability description into a CWE category, identify the vendor, and extract the cause and impact of the vulnerability.
        Provide the CWE ID (only the CWE ID of the vulnerability), a brief explanation, the vendor name, the cause of the vulnerability, and its impact.

        Description:
        ```
        {description}
        ```
        Rules for returning the vendor:
        - Return only the official/primary vendor name
        - For open source projects, return the organization maintaining it
        - If multiple vendors are mentioned, return the one responsible for the vulnerable component
        - Normalize variations of the same vendor name
        - If no clear vendor is found, return "Unknown"
        - Use official vendor names where possible and keep the same name for vulnerabilities of the same vendor

        Output:
        ```json
        {{"cwe_category": "CWE-ID", "explanation": "Brief Explanation of the CWE", "vendor": "Vendor Name", "cause": "Cause of the Vulnerability", "impact": "Impact of the Vulnerability"}}
        ```
        """
        retries = 3
        for i in range(retries):
            try:
                response = await client.chat.completions.create(
                    model="llama3.1-70b",
                    messages=[{"role": "user", "content": prompt}]
                )
                return [_extract_category(response.choices[0].message.content)]
            except Exception as e:
                print(f"Error calling Llama API (attempt {i+1}/{retries}): {e}")
                await asyncio.sleep(2 ** i)  # Exponential backoff
        return [{"cwe_category": "UNKNOWN", "explanation": str(e), "vendor": "Unknown", "cause": "", "impact": ""}]

    async def categorize_vulnerability_combined(self, description):
        """
        Combines results from all AI providers using weighted voting.
        """
        gemini_result = await self.categorize_vulnerability_gemini(description)
        gpt_result = await self.categorize_vulnerability_gpt(description)
        llama_result = await self.categorize_vulnerability_llama(description)

        # Use voting system to combine results
        return self.combine_results(
            gemini_result,
            gpt_result,
            llama_result
        )

    async def categorize_vulnerability_default(self, description):
        api_key = os.getenv('DEFAULT_API_KEY')
        base_url = os.getenv('DEFAULT_API_URL')
        model = os.getenv('DEFAULT_API_MODEL')
        
        client = AsyncOpenAI(api_key=api_key, base_url=base_url)
        prompt = f"""
        You are a security expert.
        Categorize the following vulnerability description into a CWE category, identify the vendor, and extract the cause and impact of the vulnerability.
        Provide the CWE ID (only the CWE ID of the vulnerability), a brief explanation, the vendor name, the cause of the vulnerability, and its impact.

        Description:
        ```
        {description}
        ```
        Rules for returning the vendor:
        - Return only the official/primary vendor name
        - For open source projects, return the organization maintaining it
        - If multiple vendors are mentioned, return the one responsible for the vulnerable component
        - Normalize variations of the same vendor name
        - If no clear vendor is found, return "Unknown"
        - Use official vendor names where possible and keep the same name for vulnerabilities of the same vendor

        Output:
        ```json
        {{"cwe_category": "CWE-ID", "explanation": "Brief Explanation of the CWE", "vendor": "Vendor Name", "cause": "Cause of the Vulnerability", "impact": "Impact of the Vulnerability"}}
        ```
        """
        try:
            completion = await client.chat.completions.create(
                model=model,
                messages=[{"role": "user", "content": prompt}]
            )
            result = _extract_category(completion.choices[0].message.content)
            return [result]
        except Exception as e:
            print(f"Error calling ChatGPT API: {e}")
            return [{"cwe_category": "UNKNOWN", "explanation": str(e), "vendor": "Unknown", "cause": "", "impact": ""}]

    async def categorize_vulnerability_provider(self, description):
        api_key = os.getenv('PROVIDER_API_KEY')
        base_url = os.getenv('PROVIDER_API_URL')
        model = os.getenv('PROVIDER_API_MODEL')
        type = os.getenv("PROVIDER_TYPE")
        config = os.getenv("PROVIDER_CONFIG")
                  
        prompt = f"""
            You are a security expert.
            Categorize the following vulnerability description into a CWE category, identify the vendor, and extract the cause and impact of the vulnerability.
            Provide the CWE ID (only the CWE ID of the vulnerability), a brief explanation, the vendor name, the cause of the vulnerability, and its impact.

            Description:
            ```
            {description}
            ```
            Rules for returning the vendor:
            - Return only the official/primary vendor name
            - For open source projects, return the organization maintaining it
            - If multiple vendors are mentioned, return the one responsible for the vulnerable component
            - Normalize variations of the same vendor name
            - If no clear vendor is found, return "Unknown"
            - Use official vendor names where possible and keep the same name for vulnerabilities of the same vendor

            Output:
            ```json
            {{"cwe_category": "CWE-ID", "explanation": "Brief Explanation of the CWE", "vendor": "Vendor Name", "cause": "Cause of the Vulnerability", "impact": "Impact of the Vulnerability"}}
            ```
            """
            
        if(type == 'api'):
            client = AsyncOpenAI(api_key=api_key, base_url=base_url)
            try:
                completion = await client.chat.completions.create(
                    model=model,
                    messages=[{"role": "user", "content": prompt}]
                )
                result = _extract_category(completion.choices[0].message.content)
                return [result]
            except Exception as e:
                print(f"Error calling API: {e}")
                return [{"cwe_category": "UNKNOWN", "explanation": str(e), "vendor": "Unknown", "cause": "", "impact": ""}]
        
        if(type == 'local'):
            try:
                config_dict = ''
                if(config):
                    config_string = config
                    # Dividir a string em chave e valor
                    key, value = config_string.split('=')
                    # Converter o valor para o tipo apropriado (neste caso, bool)
                    value = value == 'True'
                    # Criar um dicionário com a chave e o valor
                    config_dict = {key: value}
                tokenizer = AutoTokenizer.from_pretrained(model)
                
                model = AutoModelForCausalLM.from_pretrained(model,**config_dict)
                pipe = pipeline("text-generation", model= model, tokenizer = tokenizer)
                result = _extract_category(pipe(prompt)[0]["generated_text"])
                return [result]
            except Exception as e:
                print(f"Error calling local: {e}")
                return [{"cwe_category": "UNKNOWN", "explanation": str(e), "vendor": "Unknown", "cause": "", "impact": ""}]
        
    def categorize_vulnerability_none(self, description):
        return [{"cwe_category": "UNKNOWN", "explanation": "No categorization available",
                "vendor": "Unknown", "cause": "", "impact": ""}]

    def vote(self, responses, field):
        """
        Implement weighted voting for a specific field across AI responses.
        """
        if not responses:
            return "Unknown"

        self.weights = {
            'gemini': 1.0,
            'chatgpt': 1.0,
            'llama': 1.0
        }

        # Count occurrences with weights
        weighted_votes = {}
        for source, response in responses.items():
            value = str(response.get(field, '')).strip()
            if value:
                weight = self.weights.get(source, 1.0)
                weighted_votes[value] = weighted_votes.get(value, 0) + weight

        # Return the value with highest weighted votes
        if weighted_votes:
            return max(weighted_votes.items(), key=lambda x: x[1])[0]
        return "Unknown"

    def combine_results(self, gemini_result, gpt_result, llama_result):
        """
        Combine results from different AI sources using weighted voting.
        """
        responses = {
            'gemini': gemini_result[0] if gemini_result else {},
            'chatgpt': gpt_result[0] if gpt_result else {},
            'llama': llama_result[0] if llama_result else {}
        }

        return [{
            "cwe_category": self.vote(responses, "cwe_category"),
            "explanation": self.vote(responses, "explanation"),
            "vendor": self.vote(responses, "vendor"),
            "cause": self.vote(responses, "cause"),
            "impact": self.vote(responses, "impact")
        }]