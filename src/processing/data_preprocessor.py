import re
from processing.load_normalizer import load_normalizers

class DataPreprocessor:
    def __init__(self, normalizers):
        self.normalizers = normalizers

    def preprocess_data(self, vulnerabilities, search_params):
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
            for normalizer in self.normalizers.values():
                norm = normalizer.normalize_data(vuln, description_without_punct, truncated_description)
                if norm:
                    # Assign vendor based on search parameters
                    norm['vendor'] = next((param for param in search_params if param.lower() in description_without_punct), "Unknown")
                    norm['description_without_punct'] = description_without_punct  # Ensure this field is present
                    normalized.append(norm)
                    seen_ids[normalized_id] = {
                        'source': source,
                        'index': len(normalized) - 1
                    }
                    break
        
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