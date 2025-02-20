import re
from .normalizer import NormalizerBase

class BasicNormalizer(NormalizerBase):
    def normalize_data(self, vulnerability, description_without_punct, truncated_description, source):
        # Implement the normalization logic here
        normalized_data = {
            "id": vulnerability.get("cve", {}).get("id") or vulnerability.get("_source", {}).get("id"),
            "description": truncated_description,
            "description_without_punct": description_without_punct,
            "published": vulnerability.get("publishedDate") or vulnerability.get("_source", {}).get("published"),
            "cvss_score": vulnerability.get("impact", {}).get("baseMetricV3", {}).get("cvssV3", {}).get("baseScore") or vulnerability.get("_source", {}).get("cvss", {}).get("score"),
            "severity": vulnerability.get("impact", {}).get("baseMetricV3", {}).get("cvssV3", {}).get("baseSeverity") or vulnerability.get("_source", {}).get("cvss", {}).get("severity"),
            "source": source  # Use the source parameter
        }
        return normalized_data