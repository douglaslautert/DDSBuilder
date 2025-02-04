import os
import argparse
import re
from processing import normalizer
import data_sources.nvd_extractor as nvd_extractor
from catagorization.categorizer import Categorizer
from output import json_exporter, csv_exporter


def collect_data(search_params):
    vulnerabilities = []
    for param in search_params:
        nvd_response = nvd_extractor.get_nvd_data(param)
        vulnerabilities.extend(nvd_response.get("vulnerabilities", []))
    print("Collected vulnerabilities:", len(vulnerabilities))  # Debug
    return vulnerabilities

def preprocess_data(vulnerabilities):
    normalized = []
    seen_ids = set()
    for vuln in vulnerabilities:
        # Extract description from either "cve" or "_source"
        if vuln.get("cve"):
            description_full = next((desc.get("value", "") for desc in vuln["cve"].get("descriptions", []) if desc.get("lang") == "en"), "")
        else:
            description_full = vuln.get("_source", {}).get("description", "")
        
        # Truncate description for processing
        truncated_description = description_full[:300] if description_full else ""
        # Create a punctuation-free version for normalization
        description_without_punct = re.sub(r'[^\w\s]', '', truncated_description).lower() if truncated_description else ""

        norm = normalizer.normalize_nvd_data(vuln, description_without_punct, truncated_description)
        vuln_id = norm.get("id")
        if norm and vuln_id and vuln_id not in seen_ids:
            normalized.append(norm)
            seen_ids.add(vuln_id)
    print("Normalized vulnerabilities:", len(normalized))  # Debug
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
    parser.add_argument('--gemini-key', help="API key for Gemini")
    parser.add_argument('--chatgpt-key', help="API key for ChatGPT")
    parser.add_argument('--llama-key', help="API key for Llama")
    parser.add_argument('--vulners-key', help="API key for Vulners")
    parser.add_argument('--export-format', choices=['csv', 'json'], default='csv', help="Export format")
    parser.add_argument('--output-file', default="dataset/dds_vulnerabilities_AI.csv", help="Output file name")
    parser.add_argument('--search-params', nargs='*', help="Search parameters for vulnerabilities")
    parser.add_argument('--search-file', help="Path to a file containing search parameters")
    args = parser.parse_args()

    if args.vulners_key:
        os.environ["VULNERS_API_KEY"] = args.vulners_key
    os.environ["CSV_OUTPUT_FILE"] = args.output_file

    if args.source in ['gemini', 'combined']:
        if args.gemini_key:
            os.environ["GEMINI_API_KEY"] = args.gemini_key
        else:
            print("Gemini API key not found in environment.")
            return

    if args.source in ['chatgpt', 'combined']:
        if args.chatgpt_key:
            os.environ["CHATGPT_API_KEY"] = args.chatgpt_key
        else:
            print("ChatGPT API key not found in environment.")
            return

    if args.source in ['llama', 'combined']:
        if args.llama_key:
            os.environ["LLAMA_API_KEY"] = args.llama_key
        else:
            print("Llama API key not found in environment.")
            return

    search_params = args.search_params or []
    if args.search_file:
        search_params.extend(read_search_params_from_file(args.search_file))

    if not search_params:
        print("No search parameters provided.")
        return

    print("Collecting vulnerability data...")
    vulnerabilities = collect_data(search_params)
    if not vulnerabilities:
        print("No vulnerability data collected.")
        return

    print("Preprocessing data...")
    normalized_data = preprocess_data(vulnerabilities)
    if not normalized_data:
        print("No normalized vulnerabilities found.")
        return

    print(f"Categorizing vulnerabilities using {args.source}...")
    categorizer_obj = Categorizer()
    categorized_data = []
    for vuln in normalized_data:
        description = vuln.get("description", "")
        # Call corresponding categorization method; expect a list with a tuple.
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
        else:
            result = None

        if result:
            # result is expected to be a list containing a tuple.
            vuln["cwe_category"]    = result[0][0]
            vuln["cwe_explanation"] = result[0][1]
            vuln["vendor"]          = result[0][2]
            vuln["cause"]           = result[0][3]
            vuln["impact"]          = result[0][4]
        else:
            # Fallback if categorization fails:
            vuln["cwe_category"]    = "UNKNOWN"
            vuln["cwe_explanation"] = ""
            vuln["vendor"]          = vuln.get("vendor", "Unknown")
            vuln["cause"]           = ""
            vuln["impact"]          = ""
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
            exporter = csv_exporter.BasicCsvExporter(args.output_file)
        exporter.export(categorized_data)
    elif args.export_format == 'json':
        json_exporter.write_to_json(categorized_data, args.output_file)
    else:
        print("Unsupported export format.")

    print("Process complete.")

if __name__ == "__main__":
    main()