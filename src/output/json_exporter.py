import json
from .data_exporter import DataExporterBase

class JsonExporter(DataExporterBase):
    def export(self, data, filename):
        with open(filename, mode='w', encoding='utf-8') as file:
            json.dump(data, file, indent=4)
def write_to_json(data, filename):
    """
    Write vulnerability data to a JSON file.
    """
    with open(filename, mode="w", encoding="utf-8") as f:
        json.dump(data, f, indent=4)
