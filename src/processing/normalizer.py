from data_sources import nvd_extractor
import output.csv_exporter as csv_exporter
import re


class NormalizerBase:
    def normalize_data(self, vulnerability, description_without_punct, truncated_description):
        raise NotImplementedError("Subclasses should implement this method")


