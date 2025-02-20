import csv
import os
import categorization.categorizer as cat

class BasicCsvExporter:
    # Adjust fieldnames as needed by your vulnerability dictionary.
    fieldnames = [
        "id", "title", "description", "vendor",
        "cwe_category", "cwe_explanation", "cause", "impact",
        "published", "cvss_score", "severity", "source", "description_normalized", "explanation",
        "description_without_punct"  # Add this field to the fieldnames
    ]
    
    def __init__(self, filename):
        self.filename = filename
        # Ensure the output directory exists.
        directory = os.path.dirname(filename)
        if directory and not os.path.exists(directory):
            os.makedirs(directory)
        # Write header immediately to create/overwrite file.
        self.write_header()
        self.existing = set()

    def write_header(self):
        with open(self.filename, 'w', newline='', encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=self.fieldnames, delimiter=';')
            writer.writeheader()

    def write_row(self, row):
        if 'id' not in row or not row['id']:
            print("Warning: Row without 'id':", row)
            return
        # Append row to file.
        with open(self.filename, 'a', newline='', encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=self.fieldnames, delimiter=';')
            writer.writerow(row)
            self.existing.add(row.get('id'))

    def export(self, data):
        for item in data:
            if item.get('id') not in self.existing:
                self.write_row(item)