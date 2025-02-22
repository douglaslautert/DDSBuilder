import re
from processing.load_normalizer import load_normalizers

class DataPreprocessor:
    def __init__(self, normalizers):
        self.normalizers = normalizers

    def preprocess_data(self, vulnerabilities, search_params, source):
        """Normalize vulnerability data and handle duplicates with improved tracking."""
        normalized = []
        seen_ids = set()
        seen_cves = set()
        duplicates = []

        for vuln in vulnerabilities:
            # Normalize data
            for normalizer in self.normalizers.values():
                norm = normalizer.normalize_data(vuln, source)
                if norm:
                    vuln_id = norm.get('id')
                    cve = norm.get('id')  # Assuming 'id' contains the CVE identifier

                    # Check for duplicates
                    if vuln_id in seen_ids or cve in seen_cves:
                        duplicates.append(norm)
                        continue

                    # Assign vendor based on search parameters
                    norm['vendor'] = next((param for param in search_params if param.lower() in norm['description_without_punct']), "Unknown")
                    normalized.append(norm)
                    seen_ids.add(vuln_id)
                    seen_cves.add(cve)
                    break

        # Print detailed statistics
        print("\nDuplication Statistics:")
        print(f"Total vulnerabilities found: {len(vulnerabilities)}")
        print(f"Unique vulnerabilities after normalization: {len(normalized)}")
        print(f"Duplicates removed: {len(duplicates)}")

        if duplicates:
            for dup in duplicates:
                print(f"Duplicate Details: - {dup['id']} from {dup['source']}: {dup['description']}")

        return normalized