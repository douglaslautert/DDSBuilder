import re
from processing.load_normalizer import load_normalizers

class DataPreprocessor:
    def __init__(self, normalizers):
        self.normalizers = normalizers

    def preprocess_data(self, vulnerabilities, search_params, source):
        """Normalize vulnerability data and handle duplicates with improved tracking."""
        normalized = []
        seen_ids = {}  # Change to dict to track sources
        duplicates = []
        
        for vuln in vulnerabilities:
            # Normalize data
            for normalizer in self.normalizers.values():
                norm = normalizer.normalize_data(vuln, source)
                if norm:
                    # Assign vendor based on search parameters
                    norm['vendor'] = next((param for param in search_params if param.lower() in norm['description_without_punct']), "Unknown")
                    normalized.append(norm)
                    seen_ids[norm['id']] = {
                        'source': norm['source'],
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