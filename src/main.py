import os
import processing.normalizer as normalizer

# ***** CONFIGURATION *****
GEMINI_API_KEY = "GEMINI_API_KEY" # Replace with your Gemini API key
CHAT_API_KEY = "CHAT_API_KEY" # Replace with your Chat-GPT API Key
LLAMA_API_KEY = "LLAMA_API_KEY"
VULNERS_API_KEY = "VULNERS_API_KEY" # Replace with your actual Vulners API key
CSV_OUTPUT_FILE = "dataset/dds_vulnerabilities_AI.csv" # Change the output file name
# ***** END CONFIGURATION *****

# Define a chave de API do Gemini como uma variável de ambiente
os.environ["GOOGLE_API_KEY"] = GEMINI_API_KEY
# Define a chave de API do Chat-GPT como uma variável de ambiente
os.environ["CHAT_API_KEY"] = CHAT_API_KEY
# Define a chave de API do Deep-Seek como uma variável de ambiente
os.environ["LLAMA_API_KEY"] = LLAMA_API_KEY
# Define a chave de API do VULNERS como uma variável de ambiente
os.environ["VULNERS_API_KEY"] = VULNERS_API_KEY
# Define a saida do arquivo CSV como uma variável de ambiente
os.environ["CSV_OUTPUT_FILE"] = CSV_OUTPUT_FILE

def main():
    """Orchestrates the vulnerability search and data extraction process."""
    normalizer.normalizer()
    print(f"Vulnerability data saved to {CSV_OUTPUT_FILE}")

if __name__ == "__main__":
    main()