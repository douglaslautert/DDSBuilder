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
from output.load_exporter import load_exporters


def get_provider(provider_name):
    for model_info in MODELS_TO_EVALUATE:
        if model_info.get("provider") == provider_name:
            return {
                "model": model_info.get("model"),
                "api_key": model_info.get("api_key"),
                "site": model_info.get("site")  # Default site if not provided
            }
    return None

# Load configuration
def load_config():
    config_path = os.path.join(os.path.dirname(__file__), 'config.yaml')
    with open(config_path, 'r') as file:
        return yaml.safe_load(file)

config = load_config()

MODELS_TO_EVALUATE = config['models_to_evaluate']

async def collect_data(search_params, sources, config):
    """
    Collect vulnerability data from specified sources.
    """
    data_sources = load_data_sources(config)
    print(f"Loaded data sources: {list(data_sources.keys())}")
    vulnerabilities = []

    if 'both' in sources:
        print("Collecting data from both sources")
        tasks = [data_sources[ds_name].collect_data(search_params) for ds_name in data_sources]
        results = await asyncio.gather(*tasks)
        for result in results:
            vulnerabilities.extend(result)
    else:
        for source in sources:
            if source in data_sources:
                print(f"Collecting data from source: {source}")
                vulnerabilities.extend(await data_sources[source].collect_data(search_params))
            else:
                print(f"Unsupported data source: {source}")

    # Debug output
    print(f"Total vulnerabilities collected: {len(vulnerabilities)}")
    print("Sources breakdown:")
    for ds_name in data_sources:
        count = sum(1 for v in vulnerabilities if v.get('source') == ds_name)
        print(f"- {ds_name.capitalize()}: {count}")

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
    export_format_choices = config['exporters']

    parser.add_argument('--source', choices=['gemini', 'chatgpt', 'llama', 'combined', 'provider', 'none'], required=True,
                        help="Select the AI provider for categorization")
    parser.add_argument('--data-source', choices=data_source_choices, nargs='+', required=True,
                        help="Select the data source(s) for vulnerabilities")  
    parser.add_argument('--gemini-key', help="API key for Gemini")
    parser.add_argument('--chatgpt-key', help="API key for ChatGPT")
    parser.add_argument('--llama-key', help="API key for Llama")
    parser.add_argument('--provider', nargs='*', help="Providers of LLM")  # Add new argument for Default LLM
    parser.add_argument('--vulners-key', help="API key for Vulners")
    parser.add_argument('--new-source-key', help="API key for New Source")  # Add new source key argument
    parser.add_argument('--export-format', choices=export_format_choices, required=True, help="Export format")
    parser.add_argument('--output-file', default="dataset/dds_vulnerabilities_AI.csv", help="Output file name")
    parser.add_argument('--search-params', nargs='*', help="Search parameters for vulnerabilities")
    parser.add_argument('--search-file', help="Path to a file containing search parameters")
    args = parser.parse_args()

    # Prioritize command-line arguments over environment variables
    if args.vulners_key:
        os.environ["VULNERS_API_KEY"] = args.vulners_key
    if args.new_source_key:
        os.environ["NEW_SOURCE_API_KEY"] = args.new_source_key  # Set new source key in environment
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
           
    search_params = args.search_params or []
    if args.search_file:
        search_params.extend(read_search_params_from_file(args.search_file))

    if not search_params:
        print("No search parameters provided.")
        return

    # Create the output directory if it doesn't exist
    output_dir = os.path.dirname(args.output_file)
    if output_dir and not os.path.exists(output_dir):
        os.makedirs(output_dir)

    # Start measuring time and resources
    start_time = time.time()
    start_datetime = datetime.now()
    print(f"Program started at: {start_datetime.strftime('%Y-%m-%d %H:%M:%S')}")
    process = psutil.Process(os.getpid())
    start_memory = process.memory_info().rss

    # Load data sources
    data_sources = load_data_sources(config)
    selected_data_sources = {key: data_sources[key] for key in config['data_sources'] if key in data_sources}

    print("Collecting vulnerability data...")
    vulnerabilities = await collect_data(search_params, args.data_source, config)
    
    if not vulnerabilities:
        print("No vulnerability data collected.")
        return
    
    # Load normalizers
    normalizers = load_normalizers(config)

    print("Preprocessing data...")
    data_preprocessor = DataPreprocessor(normalizers)
    normalized_data = []
    for source_name in selected_data_sources:
        source = selected_data_sources[source_name]
        normalized_data.extend(data_preprocessor.preprocess_data(vulnerabilities, search_params, source))
    
    if not normalized_data:
        print("No normalized vulnerabilities found.")
        return

    if args.source in ['provider']:
        categorized_data = []
        categorizer_obj = Categorizer()
        
        for provider in args.provider:
            provider_type = get_provider(provider)
            print(f"Vulnerability categorizing {provider}...")
            if provider_type:
                if provider_type["api_key"]:
                    os.environ["PROVIDER_API_KEY"] = provider_type["api_key"]
                if provider_type["site"]:
                    os.environ["PROVIDER_API_URL"] = provider_type["site"]
                if provider_type["model"]:
                    os.environ["PROVIDER_API_MODEL"] = provider_type["model"]
            
            for vuln in normalized_data:
                description = vuln.get("description", "")
                result = None
                
                result = await categorizer_obj.categorize_vulnerability_provider(description)    
                
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
        # Load exporters
        
            if provider:
                output = provider + '_' + args.output_file
            exporters = load_exporters(config, output)
            if args.export_format not in exporters:
                print(f"Unsupported export format: {args.export_format}")
                return

            print("Exporting data to", output)
            exporter = exporters[args.export_format]
            exporter.export(categorized_data)

            # End measuring time and resources
            end_time = time.time()
            end_datetime = datetime.now()
            print(f"Program ended at: {end_datetime.strftime('%Y-%m-%d %H:%M:%S')}")
            end_memory = process.memory_info().rss

            print("Process completed.")
            print(f"Total execution time: {end_time - start_time:.2f} seconds")
            print(f"Memory used: {(end_memory - start_memory) / (1024 * 1024):.2f} MB")
  
    if(args.source == 'provider'):
        return
  
    if(args.source != 'none'):
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
    else:
        categorized_data = normalized_data
        # Load exporters
    exporters = load_exporters(config, args.output_file)
    if args.export_format not in exporters:
        print(f"Unsupported export format: {args.export_format}")
        return

    print("Exporting data to", args.output_file)
    exporter = exporters[args.export_format]
    exporter.export(categorized_data)

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