import os
import argparse
import yaml
import psutil
import asyncio
import time
from datetime import datetime
from processing.data_preprocessor import DataPreprocessor
from data_sources.load_data_source import load_data_sources
from processing.load_normalizer import load_normalizers
from categorization.categorizer import Categorizer
from output import json_exporter, csv_exporter


# Load configuration
def load_config():
    with open('src/config.yaml', 'r') as file:
        return yaml.safe_load(file)

async def collect_data(search_params, source):
    """
    Collect vulnerability data from specified sources.
    """
    data_sources = load_data_sources()
    print(f"Loaded data sources: {list(data_sources.keys())}")
    vulnerabilities = []

    if source in data_sources:
        print(f"Collecting data from source: {source}")
        vulnerabilities.extend(await data_sources[source].collect_data(search_params))
    elif source == 'both':
        print("Collecting data from both sources")
        tasks = [data_sources[ds_name].collect_data(search_params) for ds_name in data_sources]
        results = await asyncio.gather(*tasks)
        for result in results:
            vulnerabilities.extend(result)
    else:
        print(f"Unsupported data source: {source}")
        return []

    # Debug output
    print(f"Total vulnerabilities collected: {len(vulnerabilities)}")
    print("Sources breakdown:")
    nvd_count = sum(1 for v in vulnerabilities if v.get('source') == 'nvd')
    vulners_count = sum(1 for v in vulnerabilities if v.get('source') == 'vulners')
    print(f"- NVD: {nvd_count}")
    print(f"- Vulners: {vulners_count}")

    return vulnerabilities

def read_search_params_from_file(file_path):
    with open(file_path, 'r') as file:
        return [line.strip() for line in file.readlines()]

async def main():
    parser = argparse.ArgumentParser(
        description="DDS Builder: Build a vulnerability dataset for DDS systems using an AI provider for categorization",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )

    # Load configuration to dynamically add data source choices
    config = load_config()

    data_source_choices = config['data_sources'] + ['both']

    parser.add_argument('--source', choices=['gemini', 'chatgpt', 'llama', 'combined', 'default', 'none'], required=True,
                        help="Select the AI provider for categorization")
    parser.add_argument('--data-source', choices=data_source_choices, required=True,
                        help="Select the data source for vulnerabilities")  
    parser.add_argument('--gemini-key', help="API key for Gemini")
    parser.add_argument('--chatgpt-key', help="API key for ChatGPT")
    parser.add_argument('--llama-key', help="API key for Llama")
    parser.add_argument('--default-key', help="API key for Default LLM")
    parser.add_argument('--default-url', help="Base URL for Default LLM")
    parser.add_argument('--default-model', help="Model for Default LLM")
    parser.add_argument('--vulners-key', help="API key for Vulners")
    parser.add_argument('--export-format', choices=['csv', 'json'], default='csv', help="Export format")
    parser.add_argument('--output-file', default="dataset/dds_vulnerabilities_AI.csv", help="Output file name")
    parser.add_argument('--search-params', nargs='*', help="Search parameters for vulnerabilities")
    parser.add_argument('--search-file', help="Path to a file containing search parameters")
    args = parser.parse_args()

    # Prioritize command-line arguments over environment variables
    if args.vulners_key:
        os.environ["VULNERS_API_KEY"] = args.vulners_key
    os.environ["CSV_OUTPUT_FILE"] = args.output_file

    if args.source in ['gemini', 'combined']:
        if args.gemini_key:
            os.environ["GEMINI_API_KEY"] = args.gemini_key
        elif not os.getenv("GEMINI_API_KEY"):
            print("Gemini API key not found in environment.")
            return

    if args.source in ['chatgpt', 'combined']:
        if args.chatgpt_key:
            os.environ["CHATGPT_API_KEY"] = args.chatgpt_key
        elif not os.getenv("CHATGPT_API_KEY"):
            print("ChatGPT API key not found in environment.")
            return

    if args.source in ['llama', 'combined']:
        if args.llama_key:
            os.environ["LLAMA_API_KEY"] = args.llama_key
        elif not os.getenv("LLAMA_API_KEY"):
            print("Llama API key not found in environment.")
            return
    
    if args.source in ['default']:
        if args.default_key and args.default_url and args.default_model:
            os.environ["DEFAULT_API_URL"] = args.default_url
            os.environ["DEFAULT_API_MODEL"] = args.default_model
            os.environ["DEFAULT_API_KEY"] = args.default_key
        elif not os.getenv("DEFAULT_API_KEY") or not os.getenv("DEFAULT_API_URL") or not os.getenv("DEFAULT_API_MODEL"):
            print("Default API key, URL, ou Model não encontrado no ambiente.")
            return
        
    search_params = args.search_params or []
    if args.search_file:
        search_params.extend(read_search_params_from_file(args.search_file))

    if not search_params:
        print("No search parameters provided.")
        return

    # Start measuring time and resources
    start_time = time.time()
    start_datetime = datetime.now()
    print(f"Program started at: {start_datetime.strftime('%Y-%m-%d %H:%M:%S')}")
    process = psutil.Process(os.getpid())
    start_memory = process.memory_info().rss

    # Load data sources
    data_sources = load_data_sources()
    selected_data_sources = {key: data_sources[key] for key in config['data_sources'] if key in data_sources}

    print("Collecting vulnerability data...")
    vulnerabilities = []
    if args.data_source == 'both':
        vulnerabilities = await collect_data(search_params, 'both')
    else:
        vulnerabilities = await collect_data(search_params, args.data_source)
    
    if not vulnerabilities:
        print("No vulnerability data collected.")
        return
    
    # Load normalizers
    normalizers = load_normalizers()

    print("Preprocessing data...")
    data_preprocessor = DataPreprocessor(normalizers)
    normalized_data = []
    for source_name in selected_data_sources:
        source = selected_data_sources[source_name]
        normalized_data.extend(data_preprocessor.preprocess_data(vulnerabilities, search_params, source))
    
    if not normalized_data:
        print("No normalized vulnerabilities found.")
        return

    print("Vulnerability categorizing...")
    categorizer_obj = Categorizer()
    categorized_data = []
    
    for vuln in normalized_data:
        description = vuln.get("description", "")
        result = None
        
        if args.source == 'gemini':
            result = await categorizer_obj.categorize_vulnerability_gemini(description)
        elif args.source == 'chatgpt':
            result = await categorizer_obj.categorize_vulnerability_gpt(description)
        elif args.source == 'llama':
            result = await categorizer_obj.categorize_vulnerability_llama(description)
        elif args.source == 'combined':
            result = await categorizer_obj.categorize_vulnerability_combined(description)
        elif args.source == 'none':
            result = categorizer_obj.categorize_vulnerability_none(description)
            
        if result and len(result) > 0:
            categorization = result[0]  # Get first result dictionary
            vuln["cwe_category"] = categorization.get("cwe_category", "UNKNOWN")
            vuln["cwe_explanation"] = categorization.get("explanation", "")
            vuln["cause"] = categorization.get("cause", "")
            vuln["impact"] = categorization.get("impact", "")
            vuln["description_normalized"] = description
            vuln["explanation"] = categorization.get("explanation", "")
        else:
            # Fallback values if categorization fails
            vuln["cwe_category"] = "UNKNOWN"
            vuln["cwe_explanation"] = ""
            vuln["cause"] = ""
            vuln["impact"] = ""
            vuln["description_normalized"] = description
            vuln["explanation"] = ""
            print(f"Warning: No categorization result for vulnerability ID {vuln.get('id')}")
            
        categorized_data.append(vuln)

    print(f"Total categorized vulnerabilities: {len(categorized_data)}")

    print("Exporting data to", args.output_file)
    if args.export_format == 'csv':
        exporter = csv_exporter.BasicCsvExporter(args.output_file)
        exporter.export(categorized_data)
    elif args.export_format == 'json':
        json_exporter.write_to_json(categorized_data, args.output_file)
    else:
        print("Unsupported export format.")

    # End measuring time and resources
    end_time = time.time()
    end_datetime = datetime.now()
    print(f"Program ended at: {end_datetime.strftime('%Y-%m-%d %H:%M:%S')}")
    end_memory = process.memory_info().rss

    print("Process completed.")
    print(f"Total execution time: {end_time - start_time:.2f} seconds")
    print(f"Memory used: {(end_memory - start_memory) / (1024 * 1024):.2f} MB")

if __name__ == "__main__":
    asyncio.run(main())