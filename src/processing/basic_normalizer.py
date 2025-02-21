import re
from .normalizer import NormalizerBase

class BasicNormalizer(NormalizerBase):
    def normalize_data(self, vulnerability, source):
        # Normalize data based on the source
        normalized_data = source.normalize_data(vulnerability)
        
        # Process description
        truncated_description = normalized_data['description'][:300] if normalized_data['description'] else ""
        description_without_punct = re.sub(r'[^\w\s]', '', truncated_description).lower() if truncated_description else ""

        normalized_data.update({
            'description': truncated_description,
            'description_without_punct': description_without_punct
        })

        return normalized_data