import os
import argparse
import re
from processing import normalizer
import data_sources.nvd_extractor as nvd_extractor
import data_sources.vulners_extractor as vulners_extractor
from categorization.categorizer import Categorizer
from output import json_exporter, csv_exporter

def _collect_data(search_params, source):
    """
    Collect vulnerability data from specified sources.
    """
    vulnerabilities = []
    
    if source in ['nvd', 'both']:
        vulnerabilities.extend(nvd_extractor.collect_data(search_params))
    
    if source in ['vulners', 'both']:
        vulnerabilities.extend(vulners_extractor.collect_data(search_params))    
    # Debug output
    print(f"Total vulnerabilities collected: {len(vulnerabilities)}")
    print("Sources breakdown:")
    nvd_count = sum(1 for v in vulnerabilities if 'cve' in v)
    vulners_count = sum(1 for v in vulnerabilities if '_source' in v)
    print(f"- NVD: {nvd_count}")
    print(f"- Vulners: {vulners_count}")
    
    return vulnerabilities


def preprocess_data(vulnerabilities):
    """Normalize vulnerability data and handle duplicates with improved tracking."""
    normalized = []
    seen_ids = {}  # Change to dict to track sources
    duplicates = []
    
    for vuln in vulnerabilities:
        # Extract base information
        description_full, normalized_id, source = normalizer.extract_vulnerability_info(vuln)
        
        if not normalized_id:
            print(f"Warning: Empty ID found for vulnerability with description: {description_full[:100]}...")
            continue
            
        # Check for duplicates with source awareness
        if normalized_id in seen_ids:
            # If same source, it's a true duplicate
            if source == seen_ids[normalized_id]['source']:
                duplicates.append({
                    'id': normalized_id,
                    'source': source,
                    'reason': 'Same source duplicate'
                })
                continue
                
            # If different sources, keep both but log
            print(f"Note: ID {normalized_id} found in both {source} and {seen_ids[normalized_id]['source']}")
        
        # Process description
        truncated_description = description_full[:300] if description_full else ""
        description_without_punct = re.sub(r'[^\w\s]', '', truncated_description).lower() if truncated_description else ""

        # Normalize data
        norm = normalizer.normalize_data(vuln, description_without_punct, truncated_description)
        
        if norm:
            normalized.append(norm)
            seen_ids[normalized_id] = {
                'source': source,
                'index': len(normalized) - 1
            }
    
    # Print detailed statistics
    print("\nDuplication Statistics:")
    print(f"Total vulnerabilities found: {len(vulnerabilities)}")
    print(f"Unique vulnerabilities after normalization: {len(normalized)}")
    print(f"Duplicates removed: {len(duplicates)}")
    
    if duplicates:
        print("\nDuplicate Details:")
        for dup in duplicates:
            print(f"- {dup['id']} from {dup['source']}: {dup['reason']}")
            
    return normalized, duplicates

def read_search_params_from_file(file_path):
    with open(file_path, 'r') as file:
        return [line.strip() for line in file.readlines()]

def main():
    parser = argparse.ArgumentParser(
        description="DDS Builder: Build a vulnerability dataset for DDS systems using an AI provider for categorization",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument('--source', choices=['gemini', 'chatgpt', 'llama', 'combined', 'default','none'], required=True,
                        help="Select the AI provider for categorization")
    parser.add_argument('--data-source', choices=['nvd', 'vulners', 'both'], required=True,
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
    
    if args.source in ['default', 'combined']:
        if args.default_key and args.default_url and args.default_model:
            os.environ["DEFAULT_API_URL"] = args.default_url
            os.environ["DEFAULT_API_MODEL"] = args.default_model
            os.environ["DEFAULT_API_KEY"] = args.default_key
        elif not os.getenv("DEFAULT_API_KEY") or not os.getenv("DEFAULT_API_URL") or not os.getenv("DEFAULT_API_MODEL"):
            print("Default API key, URL, or Model not found in environment.")
            return

    search_params = args.search_params or []
    if args.search_file:
        search_params.extend(read_search_params_from_file(args.search_file))

    if not search_params:
        print("No search parameters provided.")
        return

    print("Collecting vulnerability data...")
    vulnerabilities = _collect_data(search_params, args.data_source)
    if not vulnerabilities:
        print("No vulnerability data collected.")
        return

    print("Preprocessing data...")
    normalized_data, duplicates = preprocess_data(vulnerabilities)
    if not normalized_data:
        print("No normalized vulnerabilities found.")
        return

    print("Categorizing vulnerabilities...")
    categorizer_obj = Categorizer()
    categorized_data = []
    
    for vuln in normalized_data:
        description = vuln.get("description", "")
        result = None
        
        if args.source == 'gemini':
            result = categorizer_obj.categorize_vulnerability_gemini(description)
        elif args.source == 'chatgpt':
            result = categorizer_obj.categorize_vulnerability_gpt(description)
        elif args.source == 'llama':
            result = categorizer_obj.categorize_vulnerability_llama(description)
        elif args.source == 'combined':
            result = categorizer_obj.categorize_vulnerability_combined(description)
        elif args.source == 'default':
            result = categorizer_obj.categorize_vulnerability_default(description)
        elif args.source == 'none':
            result = categorizer_obj.categorize_vulnerability_none(description)
            
        if result and len(result) > 0:
            categorization = result[0]  # Get first result dictionary
            vuln["cwe_category"] = categorization["cwe_category"]
            vuln["cwe_explanation"] = categorization["explanation"]
            vuln["vendor"] = categorization["vendor"]
            vuln["cause"] = categorization["cause"]
            vuln["impact"] = categorization["impact"]
            vuln.update(result[0])
        else:
             # Fallback values if categorization fails
            vuln["cwe_category"] = "UNKNOWN"
            vuln["cwe_explanation"] = ""
            vuln["vendor"] = vuln.get("vendor", "Unknown")
            vuln["cause"] = ""
            vuln["impact"] = ""
            print(f"Warning: No categorization result for vulnerability ID {vuln.get('id')}")
            
        categorized_data.append(vuln)

    print("Exporting data to", args.output_file)
    if args.export_format == 'csv':
        if args.source == 'gemini':
            exporter = csv_exporter.GeminiCsvExporter(args.output_file)
        elif args.source == 'chatgpt':
            exporter = csv_exporter.GptCsvExporter(args.output_file)
        elif args.source == 'llama':
            exporter = csv_exporter.LlamaCsvExporter(args.output_file)
        elif args.source == 'combined' or args.source == 'default' or args.source == 'none':
            exporter = csv_exporter.BasicCsvExporter(args.output_file)
        else:
            print("Unsupported source for CSV export.")
            return
        exporter.export(categorized_data)
    elif args.export_format == 'json':
        json_exporter.write_to_json(categorized_data, args.output_file)
    else:
        print("Unsupported export format.")

    print("Process complete.")

if __name__ == "__main__":
    main()