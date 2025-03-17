import json
import re
from datetime import datetime as dt
import google.generativeai as genai
import os
import asyncio
from openai import OpenAI, AsyncOpenAI
from transformers import AutoTokenizer, AutoModelForCausalLM, pipeline
import ast


def extract_assistant_response(raw_output, prompt):
        """
        Extract the security vulnerability information and format it as proper JSON
        regardless of how the LLM formats its output.
        """
        # Remove the original prompt if it's included
        if prompt in raw_output:
            response = raw_output.split(prompt, 1)[1]
        else:
            response = raw_output
        
        # Handle chat model markers
        if "<|assistant|>" in response:
            response = response.split("<|assistant|>", 1)[1].strip()
        elif "\n<|assistant|>\n" in response:
            response = response.split("\n<|assistant|>\n", 1)[1].strip()
        
        # Remove trailing tokens
        for end_token in ["</s>", "<|endoftext|>"]:
            if end_token in response:
                response = response.split(end_token, 1)[0].strip()
        
        # Initialize the structure we want to extract
        result = {
            "cwe_category": "Unknown",
            "explanation": "",
            "cause": "",
            "impact": ""
        }
        
        # Find CWE ID
        cwe_match = re.search(r'CWE[- ](\d+)', response)
        if cwe_match:
            result["cwe_category"] = f"CWE-{cwe_match.group(1)}"
        
        # Find Vendor
        vendor_match = re.search(r'(?:Vendor|vendor)[:\s]+([^:\n]+)', response)
        if vendor_match:
            result["vendor"] = vendor_match.group(1).strip()
        
        # Find Cause
        cause_match = re.search(r'(?:Cause|cause)[:\s]+([^\n]+(?:\n[^A-Z][^\n]+)*)', response)
        if cause_match:
            result["cause"] = cause_match.group(1).strip()
        
        # Find Impact
        impact_match = re.search(r'(?:Impact|impact)[:\s]+([^\n]+(?:\n[^A-Z][^\n]+)*)', response)
        if impact_match:
            result["impact"] = impact_match.group(1).strip()
        
        # Extract explanation - if not explicitly found, use the vulnerability description
        explanation_match = re.search(r'(?:Explanation|explanation|Vulnerability Description)[:\s]+([^\n]+(?:\n[^A-Z][^\n]+)*)', response)
        if explanation_match:
            result["explanation"] = explanation_match.group(1).strip()
        elif "explanation" in response.lower():
            # Try to extract text after "explanation:"
            parts = response.lower().split("explanation:", 1)
            if len(parts) > 1:
                explanation_text = parts[1].split("\n", 1)[0].strip()
                result["explanation"] = explanation_text
        
        # If no separate explanation was found, try to use the description from the prompt
        if not result["explanation"]:
            description_match = re.search(r'Description:\s*```\s*(.*?)\s*```', prompt, re.DOTALL)
            if description_match:
                result["explanation"] = description_match.group(1).strip()
        
        # Clean up any values
        for key in result:
            if isinstance(result[key], str):
                # Remove multiple spaces
                result[key] = re.sub(r'\s+', ' ', result[key]).strip()
                # Remove any remaining backticks
                result[key] = result[key].replace('`', '')
        
        return result

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

            Returns only the result nothing more!
            Example:
                    {{"cwe_category": "CWE-ID", "explanation": "Brief Explanation of the CWE", "vendor": "Vendor Name", "cause": "Cause of the Vulnerability", "impact": "Impact of the Vulnerability"}}

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

            local_prompt = f"""
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

                Format your response as follows:
                CWE ID: <CWE-ID number only>
                Explanation: <brief explanation of the vulnerability>
                Vendor: <vendor name>
                Cause: <cause of the vulnerability>
                Impact: <impact of the vulnerability>
                """

            try:
                tokenizer = AutoTokenizer.from_pretrained(model)
                
                if(config):
                    pairs = config.split(',')

                    # Converter cada par chave=valor em um dicionário
                    config_dict = {}
                    for pair in pairs:
                        key, value = pair.split('=')
                        config_dict[key] = value
                    model = AutoModelForCausalLM.from_pretrained(model,**config_dict)
                else:
                    model = AutoModelForCausalLM.from_pretrained(model)
                
                messages=[{"role": "user", "content": local_prompt}]
                formatted_prompt = tokenizer.apply_chat_template(messages, tokenize=False)

                pipe = pipeline("text-generation", model= model, tokenizer = tokenizer, max_new_tokens=250)
                #print(pipe(formatted_prompt)[0]["generated_text"])
                raw_output = pipe(formatted_prompt)[0]["generated_text"]
                result = extract_assistant_response(raw_output, local_prompt)
                #print(result)

                return [result]
            except Exception as e:
                print(f"Error calling local: {e}")
                return [{"cwe_category": "UNKNOWN", "explanation": str(e), "vendor": "Unknown", "cause": "", "impact": ""}]