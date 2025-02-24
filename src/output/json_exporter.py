import json
from .data_exporter import DataExporterBase

class JsonExporter(DataExporterBase):
    def __init__(self, filename):
        self.filename = filename

    def export(self, data):
        with open(self.filename, mode='w', encoding='utf-8') as file:
            json.dump(data, file, indent=4)
