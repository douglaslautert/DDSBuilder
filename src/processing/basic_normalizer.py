import re
from .normalizer import NormalizerBase

class BasicNormalizer(NormalizerBase):
    def normalize_data(self, vulnerability, description_without_punct, truncated_description):
        # Implement the normalization logic here
        normalized_data = {
            "id": vulnerability.get("cve", {}).get("id") or vulnerability.get("_source", {}).get("id"),
            "description": truncated_description,
            "description_without_punct": description_without_punct,
            # Add more fields as needed
        }
        return normalized_data