import csv
import os
import categorization.categorizer as cat

VENDORS = [
    "TiTAN DDS", "CoreDX", "Core DX", "Zhenrong DDS", "MilDDS", "Mil DDS", "GurumDDS", "InterCOM",
    "Fast DDS", "fastdds", "cyclonedds", "connext", "opendds"
]

class BasicCsvExporter:
    # Adjust fieldnames as needed by your vulnerability dictionary.
    fieldnames = [
        "id", "title", "description", "vendor",
        "cwe_category", "cwe_explanation", "cause", "impact",
        "published", "cvss_score", "severity", "source", "description_normalized", "explanation"
    ]
    
    def __init__(self, filename):
        self.filename = filename
        # Ensure the output directory exists.
        directory = os.path.dirname(filename)
        if directory and not os.path.exists(directory):
            os.makedirs(directory)
        # Write header immediately to create/overwrite file.
        self.write_header()
        self.existing = {}

    def write_header(self):
        with open(self.filename, 'w', newline='', encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=self.fieldnames, delimiter=';')
            writer.writeheader()

    def write_row(self, row):
        if 'id' not in row or not row['id']:
            print("Aviso: Linha sem chave 'id':", row)
            return
        # Append row to file.
        with open(self.filename, 'a', newline='', encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=self.fieldnames, delimiter=';')
            writer.writerow(row)
            self.existing[row.get('title')] = row.get('id')

    def export(self, data):
        for item in data:
            if item.get('title') not in self.existing:
                self.write_row(item)

class GptCsvExporter(BasicCsvExporter):
    def export(self, data):
        for item in data:
            if item.get('title') not in self.existing:
                self.write_row(item)

class GeminiCsvExporter(BasicCsvExporter):
    def export(self, data):
        for item in data:
            if item.get('title') not in self.existing:
                self.write_row(item)

class LlamaCsvExporter(BasicCsvExporter):
    def export(self, data):
        for item in data:
            if item.get('title') not in self.existing:
                self.write_row(item)

class GithubCsvExporter(BasicCsvExporter):
    def export(self, data):
        for item in data:
            if item.get('title') not in self.existing:
                self.write_row(item)

def write_rows(data, filename="output.csv"):
    exporter = BasicCsvExporter(filename)
    for item in data:
        if item.get('title') not in exporter.existing:
            exporter.write_row(item)