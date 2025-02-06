import os
import argparse
import re
from processing import normalizer
import data_sources.nvd_extractor as nvd_extractor
import data_sources.vulners_extractor as vulners_extractor
from categorization.categorizer import Categorizer
from output import json_exporter, csv_exporter


def collect_data(search_params, source):
    """
    Collect vulnerability data from specified sources.
    """
    vulnerabilities = []
    
    if source in ['nvd', 'both']:
        for param in search_params:
            nvd_response = nvd_extractor.get_nvd_data(param)
            if nvd_response and 'vulnerabilities' in nvd_response:
                vulnerabilities.extend(nvd_response['vulnerabilities'])
                print(f"Found {len(nvd_response['vulnerabilities'])} NVD vulnerabilities")
    
    if source in ['vulners', 'both']:
        for param in search_params:
            vulners_response = vulners_extractor.get_vulners_data(param)
            if vulners_response and 'data' in vulners_response and 'search' in vulners_response['data']:
                vulners_vulns = vulners_response['data']['search']
                vulnerabilities.extend(vulners_vulns)
                print(f"Found {len(vulners_vulns)} Vulners vulnerabilities")
                vulnerabilities.extend(vulners_response['data']['search'])
    
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
        if vuln.get("cve"):
            description_full = next((desc.get("value", "") for desc in vuln["cve"].get("descriptions", []) 
                                  if desc.get("lang") == "en"), "")
            vuln_id = vuln["cve"].get("id")
            source = "NVD"
        else:
            description_full = vuln.get("_source", {}).get("description", "")
            vuln_id = vuln.get("_source", {}).get("id") or vuln.get("id")
            source = "Vulners"
        
        # Normalize ID - remove prefixes and standardize format
        normalized_id = (vuln_id or "").replace("NVD:", "").replace("CVELIST:", "")
        normalized_id = normalized_id.replace("PRION:", "").replace("OSV:", "").strip()
        
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
            
    return normalized

def read_search_params_from_file(file_path):
    with open(file_path, 'r') as file:
        return [line.strip() for line in file.readlines()]

def main():
    parser = argparse.ArgumentParser(
        description="DDS Builder: Build a vulnerability dataset for DDS systems using an AI provider for categorization",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument('--source', choices=['gemini', 'chatgpt', 'llama', 'combined', 'none'], required=True,
                        help="Select the AI provider for categorization")
    parser.add_argument('--data-source', choices=['nvd', 'vulners', 'both'], required=True,
                        help="Select the data source for vulnerabilities")
    parser.add_argument('--gemini-key', help="API key for Gemini")
    parser.add_argument('--chatgpt-key', help="API key for ChatGPT")
    parser.add_argument('--llama-key', help="API key for Llama")
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

    search_params = args.search_params or []
    if args.search_file:
        search_params.extend(read_search_params_from_file(args.search_file))

    if not search_params:
        print("No search parameters provided.")
        return

    print("Collecting vulnerability data...")
    vulnerabilities = collect_data(search_params, args.data_source)
    if not vulnerabilities:
        print("No vulnerability data collected.")
        return

    print("Preprocessing data...")
    normalized_data = preprocess_data(vulnerabilities)
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
        elif args.source == 'none':
            result = categorizer_obj.categorize_vulnerability_default(description)
            
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
        elif args.source == 'combined' or args.source == 'none':
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